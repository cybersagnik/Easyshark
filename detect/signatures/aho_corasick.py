"""
Aho-Corasick string matching algorithm for fast pattern matching
"""
from typing import List, Tuple, Dict, Optional
from collections import deque, defaultdict

class AhoCorasickNode:
    def __init__(self):
        self.children: Dict[int, 'AhoCorasickNode'] = {}
        self.fail: Optional['AhoCorasickNode'] = None
        self.output: List[str] = []

class AhoCorasick:
    def __init__(self):
        self.root = AhoCorasickNode()
        self.patterns = {}
    
    def add_pattern(self, pattern: bytes, name: str):
        """Add a pattern to the automaton"""
        self.patterns[name] = pattern
        node = self.root
        
        for byte in pattern:
            if byte not in node.children:
                node.children[byte] = AhoCorasickNode()
            node = node.children[byte]
        
        node.output.append(name)
    
    def build(self):
        """Build failure links for Aho-Corasick automaton"""
        queue = deque()
        
        for child in self.root.children.values():
            child.fail = self.root
            queue.append(child)
        
        while queue:
            current = queue.popleft()
            
            for byte, child in current.children.items():
                queue.append(child)
                
                fail_node = current.fail
                
                while fail_node is not None and byte not in fail_node.children:
                    fail_node = fail_node.fail
                
                if fail_node is None:
                    child.fail = self.root
                else:
                    child.fail = fail_node.children[byte]
                
                child.output.extend(child.fail.output)
    
    def search(self, text: bytes) -> List[Tuple[int, str]]:
        """Search for patterns in text"""
        results = []
        node = self.root
        
        for i, byte in enumerate(text):
            while node is not None and byte not in node.children:
                node = node.fail
            
            if node is None:
                node = self.root
                continue
            
            node = node.children[byte]
            
            for pattern_name in node.output:
                results.append((i, pattern_name))
        
        return results