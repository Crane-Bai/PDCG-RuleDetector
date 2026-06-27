#!/usr/bin/env python3
"""
Feature Extractor for NPM Package Analysis
Feature vector extraction tool based on PDCG and predefined rules
"""

import json
import re
import argparse
from pathlib import Path
from typing import Dict, List, Set, Tuple
import pandas as pd
from collections import Counter
import networkx as nx  
# Add new imports at the top of the file
import math
from networkx.algorithms import community
def analyze_package_pdcg(package_path: str, rules_data: dict) -> Tuple[List[int], Set[str], Dict]:
    """
    Analyze the PDCG files of the entire NPM package at the specified path,
    return package-level feature vector and graph features
    
    Args:
        package_path: NPM package PDCG folder path
        rules_data: Rule knowledge base data
        
    Returns:
        tuple: (binary feature vector, hit rule ID set, graph feature dictionary)
    """
    # Initialize package-level rule ID set
    package_hit_rules = set()
    
    # Use pathlib to recursively find all .pdcg.json files
    package_dir = Path(package_path)
    if not package_dir.exists():
        raise FileNotFoundError(f"Package path does not exist: {package_path}")
    
    # Find all PDCG files
    pdcg_files = list(package_dir.rglob("*.pdcg.json"))
    
    if not pdcg_files:
        print(f"  Warning: No PDCG files found in package")
        # Return all-zero vector and empty graph features
        all_rule_ids = [rule['rule_id'] for rule in rules_data['rules']]
        empty_graph_features = _get_empty_graph_features()
        return [0] * len(all_rule_ids), set(), empty_graph_features
    
    print(f"  Found {len(pdcg_files)} PDCG files")
    
    # 2.1. Build package-level full graph
    package_graph = nx.DiGraph()
    processed_files = 0
    
    for pdcg_file in pdcg_files:
        try:
            # Load PDCG data
            with open(pdcg_file, 'r', encoding='utf-8') as f:
                pdcg_data = json.load(f)
            
            # Get filename (used for node ID prefix)
            file_prefix = pdcg_file.stem.replace('.pdcg', '')
            
            # Merge current PDCG nodes and edges into package-level graph
            _merge_pdcg_to_graph(package_graph, pdcg_data, file_prefix)
            processed_files += 1
            
        except Exception as e:
            print(f"    Warning: Failed to process file {pdcg_file.name}: {e}")
            continue
    
    print(f"  Successfully processed {processed_files}/{len(pdcg_files)} PDCG files")
    print(f"  Package-level graph stats: {package_graph.number_of_nodes()} nodes, {package_graph.number_of_edges()} edges")
    
    # 2.2. Mark malicious nodes
    _mark_malicious_nodes(package_graph, rules_data['rules'])
    
    # Count malicious nodes
    malicious_nodes = [node for node, data in package_graph.nodes(data=True) 
                      if data.get('is_malicious', False)]
    package_hit_rules = set()
    for node in malicious_nodes:
        node_rules = package_graph.nodes[node].get('hit_rules', set())
        package_hit_rules.update(node_rules)
    
    print(f"  Malicious node count: {len(malicious_nodes)}, Hit rule count: {len(package_hit_rules)}")
    
    # 3. Calculate graph features
    graph_features = calculate_graph_features(package_graph)
    
    # Generate binary feature vector (keep original logic)
    all_rule_ids = [rule['rule_id'] for rule in rules_data['rules']]
    feature_vector = _vectorize(package_hit_rules, all_rule_ids)
    
    return feature_vector, package_hit_rules, graph_features
def _merge_pdcg_to_graph(package_graph: nx.DiGraph, pdcg_data: dict, file_prefix: str) -> None:
    """
    Merge nodes and edges from a single PDCG file into the package-level graph
    
    Args:
        package_graph: Package-level NetworkX graph object
        pdcg_data: Single PDCG JSON data
        file_prefix: File prefix (used to avoid node ID conflicts)
    """
    nodes = pdcg_data.get('nodes', [])
    edges = pdcg_data.get('edges', [])
    
    # Add nodes (use file prefix to avoid ID conflicts)
    for node in nodes:
        original_id = node['id']
        unique_id = f"{file_prefix}_{original_id}"
        
        # Copy node attributes
        node_attrs = {key: value for key, value in node.items() if key != 'id'}
        node_attrs['original_id'] = original_id
        node_attrs['source_file'] = file_prefix
        
        package_graph.add_node(unique_id, **node_attrs)
    
    # Add edges (update node ID references)
    for edge in edges:
        source_id = f"{file_prefix}_{edge['source']}"
        target_id = f"{file_prefix}_{edge['target']}"
        edge_type = edge['type']
        
        # Only add edge if both source and target nodes exist
        if package_graph.has_node(source_id) and package_graph.has_node(target_id):
            package_graph.add_edge(source_id, target_id, type=edge_type)
def _mark_malicious_nodes(package_graph: nx.DiGraph, rules: list) -> None:
    """
    Optimized malicious node marking: greatly reduce invalid traversal and duplicate computation
    """
    total_nodes = package_graph.number_of_nodes()
    print(f"    Starting malicious node marking (node count: {total_nodes})")
    
    # 1. Pre-group nodes to avoid repeated full-graph scanning
    call_nodes = []
    arg_nodes = []
    
    for node_id, node_data in package_graph.nodes(data=True):
        node_type = node_data.get('type')
        if node_type == 'CALL':
            call_nodes.append(node_id)
        elif node_type == 'ARGUMENT':
            arg_nodes.append(node_id)
    
    print(f"    Node grouping: CALL={len(call_nodes)}, ARGUMENT={len(arg_nodes)}")
    
    # 2. Pre-build global edge mapping to avoid repeated computation
    edge_map = {}
    for source, target, edge_data in package_graph.edges(data=True):
        if edge_data.get('type') == 'has_arg':
            if source not in edge_map:
                edge_map[source] = []
            edge_map[source].append(target)
    
    # 3. Group by rule type to reduce invalid matching
    call_rules = []
    arg_rules = []
    combo_rules = []
    
    for rule in rules:
        pdcg_pattern = rule['pdcg_pattern']
        if 'primary_call' in pdcg_pattern:
            combo_rules.append(rule)
        elif pdcg_pattern.get('node_type') == 'CALL':
            call_rules.append(rule)
        elif pdcg_pattern.get('node_type') == 'ARGUMENT':
            arg_rules.append(rule)
    
    print(f"    Rule grouping: CALL={len(call_rules)}, ARG={len(arg_rules)}, COMBO={len(combo_rules)}")
    
    # 4. Efficient matching - only apply relevant rules to relevant node types
    matched_count = 0
    
    # Process CALL node rules
    for rule in call_rules:
        rule_id = rule['rule_id']
        pdcg_pattern = rule['pdcg_pattern']
        
        for node_id in call_nodes:
            if _fast_match_call_node(package_graph, node_id, edge_map, pdcg_pattern):
                _mark_node_malicious(package_graph, node_id, rule_id, rule)
                matched_count += 1
    
    # Process ARGUMENT node rules
    for rule in arg_rules:
        rule_id = rule['rule_id']
        pdcg_pattern = rule['pdcg_pattern']
        
        for node_id in arg_nodes:
            if _fast_match_arg_node(package_graph, node_id, pdcg_pattern):
                _mark_node_malicious(package_graph, node_id, rule_id, rule)
                matched_count += 1
    
    # Process combo rules (only for CALL nodes)
    for rule in combo_rules:
        rule_id = rule['rule_id']
        pdcg_pattern = rule['pdcg_pattern']
        
        for node_id in call_nodes:
            if _fast_match_combo_rule(package_graph, node_id, edge_map, pdcg_pattern):
                _mark_node_malicious(package_graph, node_id, rule_id, rule)
                matched_count += 1
    
    print(f"    Malicious node marking complete, hit count: {matched_count}")
def calculate_graph_features(graph: nx.DiGraph) -> Dict:
    """
    Calculate graph-theoretic features of the package-level graph (V3 - Removed cross-file features)
    """
    # 1. Extract malicious nodes and build malicious subgraph
    malicious_nodes = {node for node, data in graph.nodes(data=True) if data.get('is_malicious', False)}
    
    if not malicious_nodes:
        return _get_empty_graph_features()

    features = {}
    total_nodes = graph.number_of_nodes()
    malicious_subgraph = graph.subgraph(malicious_nodes)
    print(f"    Starting graph feature calculation (total nodes: {total_nodes}, malicious nodes: {len(malicious_nodes)})")

    # 2. Basic statistical features
    features['malicious_node_count'] = len(malicious_nodes)
    features['malicious_ratio'] = len(malicious_nodes) / total_nodes if total_nodes > 0 else 0.0
    
    category_counts = Counter(data.get('category', 'UNKNOWN') for node, data in graph.nodes(data=True) if node in malicious_nodes)
    features['category_diversity'] = len(category_counts)
    for category in ['IG', 'DT', 'DE', 'PE', 'SP']:
        features[f'{category}_ratio'] = category_counts[category] / len(malicious_nodes) if malicious_nodes else 0.0

    # 3. Malicious subgraph internal connectivity features
    print("    Calculating internal connectivity features...")
    _calculate_connectivity_features(features, malicious_subgraph, malicious_nodes)

    # 4. Centrality features (enhanced)
    print("    Calculating centrality features...")
    _calculate_centrality_features(features, graph, malicious_subgraph, malicious_nodes)

    # 5. Community structure features
    print("    Calculating community structure features...")
    _calculate_community_features(features, graph, malicious_nodes)

    # Removed cross-file collaboration feature calculation
    # print("    Calculating cross-file collaboration features...")
    # _calculate_cross_file_features_enhanced(features, graph, malicious_nodes)

    print(f"    Graph feature calculation complete")
    return features
def _calculate_connectivity_features(features: Dict, malicious_subgraph: nx.DiGraph, malicious_nodes: Set[str]):
    """Calculate connectivity features of the malicious subgraph"""
    try:
        features['malicious_internal_edges'] = malicious_subgraph.number_of_edges()
        
        # Density calculation - ensure robustness
        if len(malicious_nodes) > 1:
            features['malicious_density'] = nx.density(malicious_subgraph)
        else:
            features['malicious_density'] = 0.0
        
        # Weakly connected component count
        features['malicious_components'] = nx.number_weakly_connected_components(malicious_subgraph)
        
    except Exception as e:
        print(f"      Connectivity feature calculation failed: {e}")
        features['malicious_internal_edges'] = 0
        features['malicious_density'] = 0.0
        features['malicious_components'] = 1 if malicious_nodes else 0

def _calculate_centrality_features(features: Dict, full_graph: nx.DiGraph, malicious_subgraph: nx.DiGraph, malicious_nodes: Set[str]):
    """Calculate all centrality features and update to features dictionary"""
    malicious_nodes_list = list(malicious_nodes)
    
    # --- Centrality in full graph (measure influence in the entire package) ---
    print("      Calculating full graph centrality...")
    
    # Degree Centrality - Added
    try:
        degree_centrality = nx.degree_centrality(full_graph)
        malicious_degrees = [degree_centrality.get(n, 0) for n in malicious_nodes_list]
        features['mean_degree_centrality_full'] = sum(malicious_degrees) / len(malicious_degrees) if malicious_degrees else 0.0
        features['max_degree_centrality_full'] = max(malicious_degrees) if malicious_degrees else 0.0
    except Exception as e:
        print(f"        Full graph degree centrality calculation failed: {e}")
        features['mean_degree_centrality_full'] = 0.0
        features['max_degree_centrality_full'] = 0.0

    # PageRank
    try:
        pagerank = nx.pagerank(full_graph, alpha=0.85, tol=1.0e-4, max_iter=50)
        malicious_pageranks = [pagerank.get(n, 0) for n in malicious_nodes_list]
        features['mean_malicious_pagerank'] = sum(malicious_pageranks) / len(malicious_pageranks) if malicious_pageranks else 0.0
        features['max_malicious_pagerank'] = max(malicious_pageranks) if malicious_pageranks else 0.0
        features['sum_malicious_pagerank'] = sum(malicious_pageranks)
    except Exception as e:
        print(f"        Full graph PageRank calculation failed: {e}")
        features['mean_malicious_pagerank'] = 0.0
        features['max_malicious_pagerank'] = 0.0
        features['sum_malicious_pagerank'] = 0.0

    # Approximate betweenness centrality
    try:
        total_nodes = full_graph.number_of_nodes()
        k = min(total_nodes, max(100, int(total_nodes * 0.01)))
        betweenness = nx.betweenness_centrality(full_graph, k=k, normalized=True, seed=42)
        malicious_betweenness = [betweenness.get(n, 0) for n in malicious_nodes_list]
        features['mean_malicious_betweenness'] = sum(malicious_betweenness) / len(malicious_betweenness) if malicious_betweenness else 0.0
        features['max_malicious_betweenness'] = max(malicious_betweenness) if malicious_betweenness else 0.0
    except Exception as e:
        print(f"        Full graph betweenness centrality calculation failed: {e}")
        features['mean_malicious_betweenness'] = 0.0
        features['max_malicious_betweenness'] = 0.0

    # --- Centrality in malicious subgraph (measure importance within malicious network) ---
    print("      Calculating malicious subgraph centrality...")
    
    if len(malicious_nodes) > 1:
        # Degree centrality
        try:
            sub_degree_centrality = nx.degree_centrality(malicious_subgraph)
            sub_malicious_degrees = [sub_degree_centrality.get(n, 0) for n in malicious_nodes_list]
            features['mean_degree_centrality_sub'] = sum(sub_malicious_degrees) / len(sub_malicious_degrees) if sub_malicious_degrees else 0.0
            features['max_degree_centrality_sub'] = max(sub_malicious_degrees) if sub_malicious_degrees else 0.0
        except Exception as e:
            print(f"        Subgraph degree centrality calculation failed: {e}")
            features['mean_degree_centrality_sub'] = 0.0
            features['max_degree_centrality_sub'] = 0.0
        
        # PageRank
        try:
            sub_pagerank = nx.pagerank(malicious_subgraph, alpha=0.85, tol=1.0e-4, max_iter=50)
            sub_malicious_pageranks = [sub_pagerank.get(n, 0) for n in malicious_nodes_list]
            features['mean_pagerank_sub'] = sum(sub_malicious_pageranks) / len(sub_malicious_pageranks) if sub_malicious_pageranks else 0.0
            features['max_pagerank_sub'] = max(sub_malicious_pageranks) if sub_malicious_pageranks else 0.0
        except Exception as e:
            print(f"        Subgraph PageRank calculation failed: {e}")
            features['mean_pagerank_sub'] = 0.0
            features['max_pagerank_sub'] = 0.0
        
        # Betweenness centrality (subgraph)
        try:
            sub_betweenness = nx.betweenness_centrality(malicious_subgraph, normalized=True)
            sub_malicious_betweenness = [sub_betweenness.get(n, 0) for n in malicious_nodes_list]
            features['mean_betweenness_sub'] = sum(sub_malicious_betweenness) / len(sub_malicious_betweenness) if sub_malicious_betweenness else 0.0
            features['max_betweenness_sub'] = max(sub_malicious_betweenness) if sub_malicious_betweenness else 0.0
        except Exception as e:
            print(f"        Subgraph betweenness centrality calculation failed: {e}")
            features['mean_betweenness_sub'] = 0.0
            features['max_betweenness_sub'] = 0.0
    else:
        # Single node case
        features['mean_degree_centrality_sub'] = 0.0
        features['max_degree_centrality_sub'] = 0.0
        features['mean_pagerank_sub'] = 0.0
        features['max_pagerank_sub'] = 0.0
        features['mean_betweenness_sub'] = 0.0
        features['max_betweenness_sub'] = 0.0

def _calculate_community_features(features: Dict, graph: nx.DiGraph, malicious_nodes: Set[str]):
    """Calculate community structure features"""
    communities = []
    
    try:
        if graph.number_of_nodes() > 0:
            try:
                # Louvain algorithm requires undirected graph
                detected_communities = community.louvain_communities(graph.to_undirected(), seed=42)
                communities.extend(detected_communities)
            except Exception:
                # If Louvain fails, use weakly connected components
                communities = [c for c in nx.weakly_connected_components(graph)]
    except Exception as e:
        print(f"      Community detection failed: {e}")
        communities = []

    if not communities:
        features['max_community_maliciousness_ratio'] = 0.0
        features['malicious_community_entropy'] = 0.0
        features['num_malicious_communities'] = 0
        return

    try:
        # Calculate maliciousness ratio for each community
        community_maliciousness_ratios = []
        for community_set in communities:
            malicious_in_community = malicious_nodes.intersection(community_set)
            if len(community_set) > 0:
                community_maliciousness_ratios.append(len(malicious_in_community) / len(community_set))
        
        features['max_community_maliciousness_ratio'] = max(community_maliciousness_ratios) if community_maliciousness_ratios else 0.0
        
        # Calculate entropy of malicious node distribution across communities
        malicious_distribution = [len(malicious_nodes.intersection(c)) for c in communities]
        malicious_distribution_counts = [count for count in malicious_distribution if count > 0]
        total_malicious_in_communities = sum(malicious_distribution_counts)
        
        if total_malicious_in_communities > 0:
            probabilities = [count / total_malicious_in_communities for count in malicious_distribution_counts]
            features['malicious_community_entropy'] = -sum(p * math.log2(p) for p in probabilities if p > 0)
        else:
            features['malicious_community_entropy'] = 0.0
        
        features['num_malicious_communities'] = len(malicious_distribution_counts)
        
    except Exception as e:
        print(f"      Community feature calculation failed: {e}")
        features['max_community_maliciousness_ratio'] = 0.0
        features['malicious_community_entropy'] = 0.0
        features['num_malicious_communities'] = 0


def _get_empty_graph_features() -> Dict:
    """
    Return empty graph feature dictionary (V3 - Removed cross-file features)
    """
    return {
        # Basic statistics
        'malicious_node_count': 0,
        'malicious_ratio': 0.0,
        'category_diversity': 0,
        'IG_ratio': 0.0, 'DT_ratio': 0.0, 'DE_ratio': 0.0, 'PE_ratio': 0.0, 'SP_ratio': 0.0,
        
        # Internal connectivity
        'malicious_internal_edges': 0,
        'malicious_density': 0.0,
        'malicious_components': 0,
        
        # Full graph centrality
        'mean_degree_centrality_full': 0.0,
        'max_degree_centrality_full': 0.0,
        'mean_malicious_pagerank': 0.0,
        'max_malicious_pagerank': 0.0,
        'sum_malicious_pagerank': 0.0,
        'mean_malicious_betweenness': 0.0,
        'max_malicious_betweenness': 0.0,
        
        # Subgraph centrality
        'mean_degree_centrality_sub': 0.0,
        'max_degree_centrality_sub': 0.0,
        'mean_pagerank_sub': 0.0,
        'max_pagerank_sub': 0.0,
        'mean_betweenness_sub': 0.0,
        'max_betweenness_sub': 0.0,
        
        # Community structure features
        'num_malicious_communities': 0,
        'max_community_maliciousness_ratio': 0.0,
        'malicious_community_entropy': 0.0,
        

    }
def save_results_to_csv(results: List[Dict], output_csv: str, rules_data: dict) -> None:
    """
    Save analysis results to CSV file (V2 - Enhanced)
    """
    import pandas as pd
    
    if not results:
        raise ValueError("No results to save")
    
    df = pd.DataFrame(results)
    
    base_columns = ['package_name', 'data_type', 'label', 'hit_rules_count', 'hit_rules']
    rule_columns = [f'rule_{rule["rule_id"]}' for rule in rules_data['rules']]
    
    # New, unified graph feature columns (V2)
    graph_columns = list(_get_empty_graph_features().keys())
    
    ordered_columns = base_columns + rule_columns + graph_columns
    ordered_columns = [col for col in ordered_columns if col in df.columns]
    df = df[ordered_columns]
    
    df.to_csv(output_csv, index=False, encoding='utf-8')
    
    print(f"CSV file saved, containing the following columns:")
    print(f"  Base info columns: {len(base_columns)}")
    print(f"  Rule feature columns: {len(rule_columns)}")
    print(f"  Graph feature columns: {len([col for col in graph_columns if col in df.columns])}")
    print(f"  Total columns: {len(ordered_columns)}")


def _fast_match_call_node(graph: nx.DiGraph, node_id: str, edge_map: dict, pdcg_pattern: dict) -> bool:
    """Fast CALL node matching - avoid repeated data structure construction"""
    node_data = graph.nodes[node_id]
    callee_name = node_data.get('callee_name', '')
    
    # Check callee_name exact match
    if 'callee_name' in pdcg_pattern:
        if callee_name != pdcg_pattern['callee_name']:
            return False
    
    # Check callee_name regex match
    if 'callee_name_regex' in pdcg_pattern:
        pattern = pdcg_pattern['callee_name_regex']
        if not re.search(pattern, callee_name):
            return False
    
    # Check arguments
    if 'arguments' in pdcg_pattern:
        return _fast_check_arguments(graph, node_id, edge_map, pdcg_pattern['arguments'])
    
    return True

def _fast_match_arg_node(graph: nx.DiGraph, node_id: str, pdcg_pattern: dict) -> bool:
    """Fast ARGUMENT node matching"""
    node_data = graph.nodes[node_id]
    content = node_data.get('content', '')
    
    # Exact match
    if 'content' in pdcg_pattern:
        expected = pdcg_pattern['content']
        actual_content = content.strip('"\'')
        if actual_content == expected:
            return True
    
    # Regex match
    if 'content_regex' in pdcg_pattern:
        pattern = pdcg_pattern['content_regex']
        if re.search(pattern, content):
            return True
    
    # Contains match
    if 'content_contains' in pdcg_pattern:
        expected = pdcg_pattern['content_contains']
        if expected in content:
            return True
    
    return False

def _fast_match_combo_rule(graph: nx.DiGraph, node_id: str, edge_map: dict, pdcg_pattern: dict) -> bool:
    """Fast combo rule matching"""
    node_data = graph.nodes[node_id]
    primary_call = pdcg_pattern['primary_call']
    
    # Check primary call callee_name
    callee_name = node_data.get('callee_name', '')
    if 'callee_name_regex' in primary_call:
        pattern = primary_call['callee_name_regex']
        if not re.search(pattern, callee_name):
            return False
    
    # Check required arguments
    required_arguments = pdcg_pattern['required_arguments']
    return _fast_check_arguments(graph, node_id, edge_map, required_arguments)

def _fast_check_arguments(graph: nx.DiGraph, call_node_id: str, edge_map: dict, arguments: list) -> bool:
    """Fast argument check - use pre-built edge mapping"""
    if call_node_id not in edge_map:
        return False
    
    arg_node_ids = edge_map[call_node_id]
    
    for arg_spec in arguments:
        index = arg_spec['index']
        
        # Find argument node at specified index
        arg_node = None
        for arg_node_id in arg_node_ids:
            arg_node_candidate = graph.nodes.get(arg_node_id)
            if arg_node_candidate and arg_node_candidate.get('arg_index') == index:
                arg_node = arg_node_candidate
                break
        
        if not arg_node:
            return False
        
        content = arg_node.get('content', '')
        
        # Fast content check
        if 'content' in arg_spec:
            expected = arg_spec['content']
            actual = content.strip('"\'')
            if actual != expected:
                return False
        
        if 'content_contains' in arg_spec:
            expected = arg_spec['content_contains']
            if expected not in content:
                return False
        
        if 'content_regex' in arg_spec:
            pattern = arg_spec['content_regex']
            if not re.search(pattern, content):
                return False
    
    return True

def _mark_node_malicious(graph: nx.DiGraph, node_id: str, rule_id: str, rule: dict) -> None:
    """Mark single node as malicious - avoid repeated attribute setting"""
    node_data = graph.nodes[node_id]
    
    # Initialize malicious attributes (only on first time)
    if 'is_malicious' not in node_data:
        node_data['is_malicious'] = True
        node_data['hit_rules'] = set()
        
        # Set category (only on first time)
        category = rule.get('category', 'UNKNOWN')
        if category == 'INFORMATION_GATHERING':
            node_data['category'] = 'IG'
        elif category == 'DATA_TRANSMISSION':
            node_data['category'] = 'DT'
        elif category == 'DATA_ENCODING':
            node_data['category'] = 'DE'
        elif category == 'PAYLOAD_EXECUTION':
            node_data['category'] = 'PE'
        else:
            node_data['category'] = 'SP'
    
    # Add hit rule ID
    node_data['hit_rules'].add(rule_id)

def _vectorize(hit_rules: set, all_rule_ids: list) -> list:
    """
    Convert hit rule ID set to binary feature vector
    
    Args:
        hit_rules: Hit rule ID set
        all_rule_ids: Ordered list of all rule IDs
        
    Returns:
        list: Binary feature vector
    """
    # Create rule ID to index mapping
    rule_index_map = {rule_id: idx for idx, rule_id in enumerate(all_rule_ids)}
    
    # Create all-zero vector
    num_rules = len(all_rule_ids)
    feature_vector = [0] * num_rules
    
    # Set hit rule positions to 1
    for rule_id in hit_rules:
        if rule_id in rule_index_map:
            index = rule_index_map[rule_id]
            feature_vector[index] = 1
    
    return feature_vector
def batch_analyze_packages(pdcg_root: str, rules_file: str, output_csv: str, data_types: List[str] = ['malicious', 'benign']) -> None:
    """
    Batch analyze package-level malicious behavior features and output CSV
    
    Args:
        pdcg_root: PDCG root directory path
        rules_file: Rule file path
        output_csv: Output CSV file path
        data_types: List of data types to process
    """
    print(f"Starting batch package-level feature extraction (including graph features)")
    print(f"PDCG root directory: {pdcg_root}")
    print(f"Rule file: {rules_file}")
    print(f"Output CSV: {output_csv}")
    print(f"Processing data types: {data_types}")
    
    # Load rule base
    try:
        with open(rules_file, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
        print(f"Successfully loaded {len(rules_data['rules'])} rules")
    except Exception as e:
        print(f"Failed to load rule file: {e}")
        return
    
    # Collect all package paths
    all_packages = []
    for data_type in data_types:
        data_dir = Path(pdcg_root) / data_type
        if not data_dir.exists():
            print(f"Warning: Directory does not exist {data_dir}")
            continue
            
        label = 1 if data_type == 'malicious' else 0
        
        # Get all package directories
        package_dirs = [d for d in data_dir.iterdir() if d.is_dir()]
        print(f"Found {len(package_dirs)} packages in {data_type}")
        
        for package_dir in package_dirs:
            all_packages.append((package_dir, label, data_type))
    
    print(f"Total packages to process: {len(all_packages)}")
    
    # Analyze each package and collect results
    results = []
    failed_packages = []
    
    for i, (package_path, label, data_type) in enumerate(all_packages, 1):
        try:
            print(f"[{i}/{len(all_packages)}] Analyzing package: {package_path.name}")
            
            # Analyze package-level features (now returns three values)
            feature_vector, hit_rules, graph_features = analyze_package_pdcg(str(package_path), rules_data)
            
            # Prepare result row
            result_row = {
                'package_name': package_path.name,
                'data_type': data_type,
                'label': label,
                'hit_rules_count': len(hit_rules),
                'hit_rules': ','.join(sorted(hit_rules)) if hit_rules else '',
            }
            
            # Add binary feature column for each rule
            all_rule_ids = [rule['rule_id'] for rule in rules_data['rules']]
            for j, rule_id in enumerate(all_rule_ids):
                result_row[f'rule_{rule_id}'] = feature_vector[j]
            
            # Add graph feature columns
            result_row.update(graph_features)
            
            results.append(result_row)
            
            print(f"  Success: Hit {len(hit_rules)} rules, {graph_features['malicious_node_count']} malicious nodes")
            
        except Exception as e:
            print(f"  Failed: {e}")
            failed_packages.append((package_path.name, str(e)))
    
    # Save as CSV
    if results:
        save_results_to_csv(results, output_csv, rules_data)
        print(f"\nSuccessfully saved {len(results)} package features to: {output_csv}")
    else:
        print("\nNo successfully analyzed packages, cannot generate CSV")
    
    # Output statistics
    print_batch_summary(results, failed_packages, data_types)

def print_batch_summary(results: List[Dict], failed_packages: List, data_types: List[str]) -> None:
    """Print batch processing summary"""
    print("\n" + "="*80)
    print("Batch package-level feature extraction complete!")
    print("="*80)
    
    if results:
        # Statistics by data type
        for data_type in data_types:
            type_results = [r for r in results if r['data_type'] == data_type]
            if type_results:
                hit_counts = [r['hit_rules_count'] for r in type_results]
                avg_hits = sum(hit_counts) / len(hit_counts)
                max_hits = max(hit_counts)
                min_hits = min(hit_counts)
                
                print(f"\n{data_type.upper()} Data statistics:")
                print(f"  Processed packages: {len(type_results)}")
                print(f"  Average hit rules: {avg_hits:.1f}")
                print(f"  Max hit rules: {max_hits}")
                print(f"  Min hit rules: {min_hits}")
        
        # Overall statistics
        total_packages = len(results)
        total_hits = sum(r['hit_rules_count'] for r in results)
        avg_hits_overall = total_hits / total_packages if total_packages > 0 else 0
        
        print(f"\nOverall statistics:")
        print(f"  Successfully processed packages: {total_packages}")
        print(f"  Failed packages: {len(failed_packages)}")
        print(f"  Total hit rule count: {total_hits}")
        print(f"  Average hit rules per package: {avg_hits_overall:.1f}")
        
        # Most active rules
        all_hit_rules = []
        for r in results:
            if r['hit_rules']:
                all_hit_rules.extend(r['hit_rules'].split(','))
        
        if all_hit_rules:
            from collections import Counter
            rule_counter = Counter(all_hit_rules)
            top_rules = rule_counter.most_common(10)
            
            print(f"\nMost frequently hit rules (Top 10):")
            for rule_id, count in top_rules:
                percentage = (count / total_packages) * 100
                print(f"  {rule_id}: {count} times ({percentage:.1f}%)")
    
    if failed_packages:
        print(f"\nFailed packages:")
        for pkg_name, error in failed_packages[:10]:  # Only show top 10
            print(f"  {pkg_name}: {error}")
        if len(failed_packages) > 10:
            print(f"  ... {len(failed_packages) - 10} more failed packages")
    
    print("="*80)

class DirectFeatureProcessor:
    """
    Direct feature processor - for processing unclassified PDCG files
    Does not distinguish benign/malicious, directly processes all PDCG files from input directory
    """
    
    def __init__(self, input_dir: str, output_dir: str, rules_data: dict):
        """
        Initialize direct feature processor
        
        Args:
            input_dir: Input PDCG file directory
            output_dir: Output feature file directory
            rules_data: Rule knowledge base data
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.rules_data = rules_data
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.processed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.start_time = None
        self.failed_packages = []
    
    def process_direct(self) -> None:
        """Execute direct processing mode"""
        print(f"Starting direct feature extraction mode")
        print(f"Input directory: {self.input_dir}")
        print(f"Output directory: {self.output_dir}")
        print(f"Rule count: {len(self.rules_data['rules'])}")
        print("-" * 60)
        
        if not self.input_dir.exists():
            raise FileNotFoundError(f"Input directory does not exist: {self.input_dir}")
        
        self.start_time = pd.Timestamp.now()
        
        # Collect all PDCG package directories
        package_dirs = self._collect_package_dirs()
        
        if not package_dirs:
            print("No PDCG package directories found")
            return
        
        print(f"Found {len(package_dirs)} package directories")
        
        # Process each package
        results = []
        for i, package_dir in enumerate(package_dirs, 1):
            try:
                print(f"[{i}/{len(package_dirs)}] Processing package: {package_dir.name}")
                
                # Analyze package features
                feature_vector, hit_rules, graph_features = analyze_package_pdcg(str(package_dir), self.rules_data)
                
                # Prepare result
                result_row = {
                    'package_name': package_dir.name,
                    'data_type': 'unknown',  # Direct mode does not distinguish type
                    'label': -1,  # Unknown label
                    'hit_rules_count': len(hit_rules),
                    'hit_rules': ','.join(sorted(hit_rules)) if hit_rules else '',
                }
                
                # Add rule features
                all_rule_ids = [rule['rule_id'] for rule in self.rules_data['rules']]
                for j, rule_id in enumerate(all_rule_ids):
                    result_row[f'rule_{rule_id}'] = feature_vector[j]
                
                # Add graph features
                result_row.update(graph_features)
                
                results.append(result_row)
                self.processed_count += 1
                
                print(f"  Success: Hit {len(hit_rules)} rules, {graph_features['malicious_node_count']} malicious nodes")
                
            except Exception as e:
                print(f"  Failed: {e}")
                self.failed_count += 1
                self.failed_packages.append((package_dir.name, str(e)))
        
        # Save results
        if results:
            output_csv = self.output_dir / "direct_features.csv"
            save_results_to_csv(results, str(output_csv), self.rules_data)
            print(f"\nSuccessfully saved {len(results)} package features to: {output_csv}")
        else:
            print("\nNo successfully analyzed packages, cannot generate CSV")
        
        # Print summary
        self._print_summary()
    
    def _collect_package_dirs(self) -> List[Path]:
        """
        Collect all package directories - follow original batch processing logic
        Only process direct subfolders under input directory, each subfolder represents a sample
        """
        package_dirs = []
        
        # Only get direct subdirectories under input directory (consistent with original batch_analyze_packages logic)
        for item in self.input_dir.iterdir():
            if item.is_dir():
                # Check if directory contains PDCG files (can be in subdirectories)
                pdcg_files = list(item.rglob("*.pdcg.json"))
                if pdcg_files:
                    package_dirs.append(item)
                else:
                    print(f"  Warning: No PDCG files found in directory {item.name}, skipping")
        
        # Sort
        package_dirs.sort()
        
        return package_dirs
    
    def _print_summary(self) -> None:
        """Print processing summary"""
        end_time = pd.Timestamp.now()
        duration = end_time - self.start_time
        
        print("\n" + "="*80)
        print("Direct feature extraction complete!")
        print("="*80)
        print(f"Processing time: {duration}")
        print(f"Successfully processed: {self.processed_count} packages")
        print(f"Failed: {self.failed_count} packages")
        print(f"Total: {self.processed_count + self.failed_count} packages")
        
        if self.failed_packages:
            print(f"\nFailed packages:")
            for pkg_name, error in self.failed_packages[:10]:
                print(f"  {pkg_name}: {error}")
            if len(self.failed_packages) > 10:
                print(f"  ... {len(self.failed_packages) - 10} more failed packages")
        
        print("="*80)

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="NPM package malicious behavior feature extraction tool - Supports single package, batch and direct modes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  # Single package analysis
  python feature_extractor.py /path/to/npm/package
  
  # Batch package-level analysis (classified mode)
  python feature_extractor.py --batch ... --output features.csv
  python feature_extractor.py --batch ... --output features.csv --types malicious benign
  
  # Direct mode (does not distinguish benign/malicious)
  python feature_extractor.py --mode direct --input-dir /path/to/pdcg/files --output-dir /path/to/output
        """
    )
    
    parser.add_argument(
        'package_path',
        nargs='?',
        help='Single package mode: NPM package folder path'
    )
    
    parser.add_argument(
        '--mode',
        choices=['classified', 'direct'],
        default='classified',
        help='Processing mode: classified (default) or direct (does not distinguish benign/malicious)'
    )
    
    parser.add_argument(
        '--batch',
        help='Batch mode: PDCG root directory path'
    )
    
    parser.add_argument(
        '--output',
        help='Batch mode: Output CSV file path'
    )
    
    parser.add_argument(
        '--input-dir',
        help='Direct mode: Input PDCG file directory path'
    )
    
    parser.add_argument(
        '--output-dir',
        help='Direct mode: Output feature file directory path'
    )
    
    parser.add_argument(
        '--types',
        nargs='+',
        default=['malicious', 'benign'],
        choices=['malicious', 'benign'],
        help='Batch mode: Data types to process'
    )
    
    parser.add_argument(
        '--rules',
        default=r'...',
        help='Rule knowledge base JSON file path (default: malicious_rules.json)'
    )
    
    args = parser.parse_args()
    
    try:
        # Load rule file
        print(f"Loading rule file: {args.rules}")
        with open(args.rules, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
        print(f"Successfully loaded {len(rules_data['rules'])} rules")
        
        if args.mode == 'direct':
            # Direct mode
            if not args.input_dir or not args.output_dir:
                print("Error: Direct mode requires --input-dir and --output-dir parameters")
                return
            
            # Verify input directory exists
            if not Path(args.input_dir).exists():
                print(f"Error: Input directory does not exist: {args.input_dir}")
                return
            
            # Create and run direct processor
            processor = DirectFeatureProcessor(args.input_dir, args.output_dir, rules_data)
            processor.process_direct()
            
        elif args.batch:
            # Batch mode (classified mode)
            if not args.output:
                print("Error: Batch mode requires --output parameter")
                return
                
            batch_analyze_packages(
                pdcg_root=args.batch,
                rules_file=args.rules,
                output_csv=args.output,
                data_types=args.types
            )
            
        elif args.package_path:
            # Single package mode
            print("-" * 60)
            
            print(f"Starting analysis of package: {args.package_path}")
            feature_vector, hit_rules, graph_features = analyze_package_pdcg(args.package_path, rules_data)
            
            # Output results (single package mode) - Removed cross-file collaboration display
            print("-" * 60)
            print("Analysis results:")
            print(f"Package path: {args.package_path}")
            print(f"Hit rule count: {len(hit_rules)}")
            print(f"Hit rule IDs: {sorted(hit_rules) if hit_rules else 'None'}")
            print(f"Feature vector dimension: {len(feature_vector)}")
            print(f"Feature vector: {feature_vector}")
            
            # Display graph feature summary (removed cross-file collaboration)
            print(f"\nGraph feature summary:")
            print(f"  Malicious node count: {graph_features.get('malicious_node_count', 0)}")
            print(f"  Malicious density: {graph_features.get('malicious_density', 0):.3f}")
            print(f"  Category diversity: {graph_features.get('category_diversity', 0)}")
            print(f"  Community count: {graph_features.get('num_malicious_communities', 0)}")
            
            if hit_rules:
                print("\nHit rule details:")
                for rule in rules_data['rules']:
                    if rule['rule_id'] in hit_rules:
                        print(f"  {rule['rule_id']}: {rule['name']} ({rule['category']})")
        else:
            parser.print_help()
            
    except FileNotFoundError as e:
        print(f"Error: File does not exist - {e}")
    except json.JSONDecodeError as e:
        print(f"Error: JSON parsing failed - {e}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()