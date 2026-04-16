// Real-world program #6: Tree Traversal with Recursive and Iterative Approaches
// Features: ES2015 classes, generators, Symbol.iterator, recursion, data structures

class TreeNode {
    constructor(value, children = []) {
        this.value = value;
        this.children = Array.isArray(children) ? children : [];
        this.metadata = {
            id: Math.random().toString(36).substr(2, 9),
            created: Date.now(),
            depth: null // Will be set during traversal
        };
    }

    // Add a child node
    addChild(node) {
        if (node instanceof TreeNode) {
            this.children.push(node);
        } else {
            // Create new node from value
            this.children.push(new TreeNode(node));
        }
        return this;
    }

    // Remove a child node
    removeChild(node) {
        const index = this.children.indexOf(node);
        if (index !== -1) {
            this.children.splice(index, 1);
        }
        return this;
    }

    // Find child by value
    findChild(value) {
        return this.children.find(child => child.value === value);
    }

    // Check if this is a leaf node
    isLeaf() {
        return this.children.length === 0;
    }

    // Get degree (number of children)
    getDegree() {
        return this.children.length;
    }

    // Clone the node (shallow)
    clone() {
        const cloned = new TreeNode(this.value);
        cloned.metadata = { ...this.metadata };
        return cloned;
    }
}

class Tree {
    constructor(root = null) {
        this.root = root;
        this.stats = {
            traversals: 0,
            nodesVisited: 0,
            maxDepth: 0
        };
    }

    // Set the root node
    setRoot(node) {
        this.root = node instanceof TreeNode ? node : new TreeNode(node);
        return this;
    }

    // Get tree height (depth)
    getHeight() {
        if (!this.root) return 0;
        return this._getNodeHeight(this.root);
    }

    _getNodeHeight(node) {
        if (!node || node.isLeaf()) return 1;

        let maxChildHeight = 0;
        for (const child of node.children) {
            maxChildHeight = Math.max(maxChildHeight, this._getNodeHeight(child));
        }

        return 1 + maxChildHeight;
    }

    // Count total nodes in tree
    getNodeCount() {
        if (!this.root) return 0;

        let count = 0;
        for (const node of this.traverseDepthFirst()) {
            count++;
        }
        return count;
    }

    // === RECURSIVE TRAVERSAL METHODS ===

    // Depth-first traversal (recursive) - Pre-order
    *traverseDepthFirstRecursive(node = this.root, depth = 0) {
        if (!node) return;

        // Update metadata
        node.metadata.depth = depth;
        this.stats.nodesVisited++;
        this.stats.maxDepth = Math.max(this.stats.maxDepth, depth);

        // Yield current node (pre-order)
        yield { node, depth, type: 'recursive-dfs' };

        // Recursively traverse children
        for (const child of node.children) {
            yield* this.traverseDepthFirstRecursive(child, depth + 1);
        }
    }

    // Breadth-first traversal (recursive) - Level by level
    *traverseBreadthFirstRecursive() {
        if (!this.root) return;

        const levels = this._collectLevelsRecursive(this.root, 0, []);

        for (let levelIndex = 0; levelIndex < levels.length; levelIndex++) {
            for (const nodeData of levels[levelIndex]) {
                this.stats.nodesVisited++;
                yield {
                    node: nodeData.node,
                    depth: levelIndex,
                    type: 'recursive-bfs'
                };
            }
        }
    }

    _collectLevelsRecursive(node, depth, levels) {
        if (!node) return levels;

        // Ensure level array exists
        if (!levels[depth]) {
            levels[depth] = [];
        }

        // Add current node to its level
        levels[depth].push({ node, depth });
        node.metadata.depth = depth;
        this.stats.maxDepth = Math.max(this.stats.maxDepth, depth);

        // Recursively collect children's levels
        for (const child of node.children) {
            this._collectLevelsRecursive(child, depth + 1, levels);
        }

        return levels;
    }

    // === ITERATIVE TRAVERSAL METHODS ===

    // Depth-first traversal (iterative) using stack
    *traverseDepthFirstIterative() {
        if (!this.root) return;

        const stack = [{ node: this.root, depth: 0 }];

        while (stack.length > 0) {
            const { node, depth } = stack.pop();

            // Update metadata
            node.metadata.depth = depth;
            this.stats.nodesVisited++;
            this.stats.maxDepth = Math.max(this.stats.maxDepth, depth);

            yield { node, depth, type: 'iterative-dfs' };

            // Add children to stack (reverse order for left-to-right traversal)
            for (let i = node.children.length - 1; i >= 0; i--) {
                stack.push({ node: node.children[i], depth: depth + 1 });
            }
        }
    }

    // Breadth-first traversal (iterative) using queue
    *traverseBreadthFirstIterative() {
        if (!this.root) return;

        const queue = [{ node: this.root, depth: 0 }];

        while (queue.length > 0) {
            const { node, depth } = queue.shift();

            // Update metadata
            node.metadata.depth = depth;
            this.stats.nodesVisited++;
            this.stats.maxDepth = Math.max(this.stats.maxDepth, depth);

            yield { node, depth, type: 'iterative-bfs' };

            // Add children to queue
            for (const child of node.children) {
                queue.push({ node: child, depth: depth + 1 });
            }
        }
    }

    // === SPECIALIZED TRAVERSAL METHODS ===

    // Post-order traversal (children before parent)
    *traversePostOrder(node = this.root, depth = 0) {
        if (!node) return;

        // Traverse children first
        for (const child of node.children) {
            yield* this.traversePostOrder(child, depth + 1);
        }

        // Then yield current node
        node.metadata.depth = depth;
        this.stats.nodesVisited++;
        this.stats.maxDepth = Math.max(this.stats.maxDepth, depth);

        yield { node, depth, type: 'post-order' };
    }

    // Level-order traversal with level information
    *traverseLevelOrder() {
        if (!this.root) return;

        let currentLevel = [this.root];
        let depth = 0;

        while (currentLevel.length > 0) {
            const nextLevel = [];

            yield { level: depth, nodes: currentLevel.map(n => n.value), type: 'level-order' };

            for (const node of currentLevel) {
                node.metadata.depth = depth;
                this.stats.nodesVisited++;
                for (const child of node.children) {
                    nextLevel.push(child);
                }
            }

            currentLevel = nextLevel;
            depth++;
        }

        this.stats.maxDepth = depth - 1;
    }

    // Find nodes matching a predicate
    *findNodes(predicate) {
        for (const { node, depth } of this.traverseDepthFirstRecursive()) {
            if (predicate(node)) {
                yield { node, depth, found: true };
            }
        }
    }

    // Default iterator (depth-first)
    *[Symbol.iterator]() {
        yield* this.traverseDepthFirstIterative();
    }

    // === CONVENIENCE METHODS ===

    // Alias for default traversal
    *traverseDepthFirst() {
        this.stats.traversals++;
        yield* this.traverseDepthFirstIterative();
    }

    // Reset statistics
    resetStats() {
        this.stats = {
            traversals: 0,
            nodesVisited: 0,
            maxDepth: 0
        };
        return this;
    }

    // Get tree statistics
    getStats() {
        return {
            ...this.stats,
            nodeCount: this.getNodeCount(),
            height: this.getHeight(),
            timestamp: Date.now()
        };
    }

    // Convert tree to array representation
    toArray(traversalType = 'dfs') {
        const result = [];
        const traversal = traversalType === 'bfs' ?
            this.traverseBreadthFirstIterative() :
            this.traverseDepthFirstIterative();

        for (const { node, depth } of traversal) {
            result.push({
                value: node.value,
                depth,
                id: node.metadata.id,
                isLeaf: node.isLeaf()
            });
        }

        return result;
    }
}

// Tree Builder utility class
class TreeBuilder {
    static fromArray(arr, childrenKey = 'children') {
        if (!Array.isArray(arr) || arr.length === 0) {
            return new Tree();
        }

        const buildNode = (item) => {
            const node = new TreeNode(item.value || item);

            if (item[childrenKey]) {
                for (const child of item[childrenKey]) {
                    node.addChild(buildNode(child));
                }
            }

            return node;
        };

        const root = buildNode(arr[0]);
        return new Tree(root);
    }

    static balanced(depth, branchingFactor = 2) {
        if (depth <= 0) return new Tree();

        let nodeCounter = 1;
        const createNode = (currentDepth) => {
            const node = new TreeNode(`Node${nodeCounter++}`);

            if (currentDepth < depth) {
                for (let i = 0; i < branchingFactor; i++) {
                    node.addChild(createNode(currentDepth + 1));
                }
            }

            return node;
        };

        return new Tree(createNode(1));
    }

    static fromNestedObject(obj, valueKey = 'value') {
        const buildFromObject = (item, key) => {
            const value = typeof item === 'object' && valueKey in item ?
                item[valueKey] : (key || 'root');

            const node = new TreeNode(value);

            if (typeof item === 'object') {
                for (const [childKey, childValue] of Object.entries(item)) {
                    if (childKey !== valueKey) {
                        node.addChild(buildFromObject(childValue, childKey));
                    }
                }
            }

            return node;
        };

        return new Tree(buildFromObject(obj));
    }
}

// Test the tree traversal system
function testTreeTraversal() {
    console.log('Testing Tree Traversal with Recursive and Iterative Approaches...');

    // Create a sample tree structure
    const root = new TreeNode('A');
    const nodeB = new TreeNode('B');
    const nodeC = new TreeNode('C');
    const nodeD = new TreeNode('D');
    const nodeE = new TreeNode('E');
    const nodeF = new TreeNode('F');
    const nodeG = new TreeNode('G');

    // Build tree structure:
    //       A
    //      /|\
    //     B C D
    //    /| |  \
    //   E F G  (leaf)

    root.addChild(nodeB).addChild(nodeC).addChild(nodeD);
    nodeB.addChild(nodeE).addChild(nodeF);
    nodeC.addChild(nodeG);

    const tree = new Tree(root);

    // Test different traversal methods
    const results = {
        recursiveDFS: [],
        iterativeDFS: [],
        recursiveBFS: [],
        iterativeBFS: [],
        postOrder: [],
        levelOrder: []
    };

    console.log('Tree structure created. Testing traversal methods...');

    // Test recursive DFS
    for (const { node, depth } of tree.traverseDepthFirstRecursive()) {
        results.recursiveDFS.push(`${node.value}:${depth}`);
    }

    // Reset stats between tests
    tree.resetStats();

    // Test iterative DFS
    for (const { node, depth } of tree.traverseDepthFirstIterative()) {
        results.iterativeDFS.push(`${node.value}:${depth}`);
    }

    tree.resetStats();

    // Test recursive BFS
    for (const { node, depth } of tree.traverseBreadthFirstRecursive()) {
        results.recursiveBFS.push(`${node.value}:${depth}`);
    }

    tree.resetStats();

    // Test iterative BFS
    for (const { node, depth } of tree.traverseBreadthFirstIterative()) {
        results.iterativeBFS.push(`${node.value}:${depth}`);
    }

    tree.resetStats();

    // Test post-order
    for (const { node, depth } of tree.traversePostOrder()) {
        results.postOrder.push(`${node.value}:${depth}`);
    }

    tree.resetStats();

    // Test level-order
    for (const { level, nodes } of tree.traverseLevelOrder()) {
        results.levelOrder.push(`Level${level}:[${nodes.join(',')}]`);
    }

    // Test tree builder utilities
    const balancedTree = TreeBuilder.balanced(3, 2);
    const balancedArray = balancedTree.toArray();

    const nestedObj = {
        value: 'root',
        users: {
            value: 'users',
            admin: 'adminUser',
            regular: 'regularUser'
        },
        data: {
            value: 'data',
            cache: 'cacheData',
            temp: 'tempData'
        }
    };

    const objTree = TreeBuilder.fromNestedObject(nestedObj);
    const objArray = objTree.toArray();

    // Test node finding
    const foundNodes = [];
    for (const { node, depth } of tree.findNodes(n => n.value.charCodeAt(0) >= 67)) { // C and above
        foundNodes.push(`${node.value}:${depth}`);
    }

    // Get final statistics
    const stats = tree.getStats();

    return {
        traversalResults: results,
        treeInfo: {
            height: tree.getHeight(),
            nodeCount: tree.getNodeCount(),
            stats
        },
        builderTests: {
            balancedTree: balancedArray.slice(0, 5), // First 5 nodes
            objectTree: objArray
        },
        searchResults: {
            foundNodes
        },
        verification: {
            dfsMatchesIterative: JSON.stringify(results.recursiveDFS) === JSON.stringify(results.iterativeDFS),
            bfsMatchesIterative: JSON.stringify(results.recursiveBFS) === JSON.stringify(results.iterativeBFS),
            postOrderWorking: results.postOrder.length > 0,
            levelOrderWorking: results.levelOrder.length > 0
        }
    };
}

// Execute the test
const result = testTreeTraversal();
console.log('\nTree Traversal Test Results:');
console.log(JSON.stringify(result, null, 2));

// Export for module testing
if (typeof module !== 'undefined') {
    module.exports = { TreeNode, Tree, TreeBuilder };
}