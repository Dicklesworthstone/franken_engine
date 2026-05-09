// Macro-Benchmark 2: Tree Traversal
// Tests object creation, recursive algorithms, DFS/BFS traversal, and serialization

class TreeNode {
    constructor(value, left = null, right = null) {
        this.value = value;
        this.left = left;
        this.right = right;
        this.metadata = {
            id: Math.floor(Math.random() * 1000000),
            created: new Date().toISOString(),
            visits: 0
        };
    }

    // Add methods to the tree node for more realistic behavior
    visit() {
        this.metadata.visits++;
        return this.value;
    }

    isLeaf() {
        return !this.left && !this.right;
    }

    getChildCount() {
        let count = 0;
        if (this.left) count++;
        if (this.right) count++;
        return count;
    }

    serialize() {
        return {
            value: this.value,
            metadata: this.metadata,
            hasLeft: !!this.left,
            hasRight: !!this.right,
            isLeaf: this.isLeaf(),
            childCount: this.getChildCount()
        };
    }
}

function buildBalancedBinaryTree(depth, valueGenerator = (i) => i) {
    if (depth <= 0) return null;

    // Calculate the number of nodes in a perfect binary tree of given depth
    const nodeCount = Math.pow(2, depth) - 1;
    const nodes = [];

    // Generate all values first
    for (let i = 0; i < nodeCount; i++) {
        nodes.push(valueGenerator(i + 1));
    }

    // Build tree level by level using a queue-based approach
    function buildTree(values) {
        if (values.length === 0) return null;

        const root = new TreeNode(values[0]);
        const queue = [{ node: root, startIndex: 1 }];

        while (queue.length > 0) {
            const { node, startIndex } = queue.shift();
            const leftIndex = startIndex;
            const rightIndex = startIndex + 1;

            if (leftIndex < values.length) {
                node.left = new TreeNode(values[leftIndex]);
                queue.push({ node: node.left, startIndex: rightIndex + 1 });
            }

            if (rightIndex < values.length) {
                node.right = new TreeNode(values[rightIndex]);
                const nextLeftStart = rightIndex + 1 + Math.pow(2, getDepth(node.right));
                queue.push({ node: node.right, startIndex: nextLeftStart });
            }
        }

        return root;
    }

    return buildTree(nodes);
}

function getDepth(node) {
    if (!node) return 0;
    return Math.max(getDepth(node.left), getDepth(node.right)) + 1;
}

function depthFirstSearch(root, visitCallback = null) {
    const result = [];
    const stats = { nodesVisited: 0, leavesFound: 0, maxDepth: 0 };

    function dfsRecursive(node, depth = 0) {
        if (!node) return;

        stats.nodesVisited++;
        stats.maxDepth = Math.max(stats.maxDepth, depth);

        const value = node.visit();
        result.push(value);

        if (visitCallback) visitCallback(node, depth);
        if (node.isLeaf()) stats.leavesFound++;

        // Traverse left subtree
        dfsRecursive(node.left, depth + 1);
        // Traverse right subtree
        dfsRecursive(node.right, depth + 1);
    }

    dfsRecursive(root);
    return { result, stats };
}

function breadthFirstSearch(root, visitCallback = null) {
    if (!root) return { result: [], stats: { nodesVisited: 0, leavesFound: 0, maxDepth: 0 } };

    const result = [];
    const queue = [{ node: root, depth: 0 }];
    const stats = { nodesVisited: 0, leavesFound: 0, maxDepth: 0 };

    while (queue.length > 0) {
        const { node, depth } = queue.shift();

        stats.nodesVisited++;
        stats.maxDepth = Math.max(stats.maxDepth, depth);

        const value = node.visit();
        result.push(value);

        if (visitCallback) visitCallback(node, depth);
        if (node.isLeaf()) stats.leavesFound++;

        // Add children to queue
        if (node.left) queue.push({ node: node.left, depth: depth + 1 });
        if (node.right) queue.push({ node: node.right, depth: depth + 1 });
    }

    return { result, stats };
}

function inOrderTraversal(root) {
    const result = [];
    const stats = { nodesVisited: 0 };

    function inOrderRecursive(node) {
        if (!node) return;

        // Traverse left subtree
        inOrderRecursive(node.left);

        // Visit current node
        stats.nodesVisited++;
        result.push(node.visit());

        // Traverse right subtree
        inOrderRecursive(node.right);
    }

    inOrderRecursive(root);
    return { result, stats };
}

function serializeTree(root) {
    const serialized = [];
    const stats = { totalNodes: 0, totalLeaves: 0 };

    function serializeRecursive(node) {
        if (!node) return null;

        stats.totalNodes++;
        if (node.isLeaf()) stats.totalLeaves++;

        return {
            data: node.serialize(),
            left: serializeRecursive(node.left),
            right: serializeRecursive(node.right)
        };
    }

    const tree = serializeRecursive(root);
    return { tree, stats };
}

function findNodesWithCondition(root, condition) {
    const matches = [];

    function searchRecursive(node, depth = 0) {
        if (!node) return;

        if (condition(node, depth)) {
            matches.push({
                value: node.value,
                depth: depth,
                metadata: node.metadata,
                isLeaf: node.isLeaf()
            });
        }

        searchRecursive(node.left, depth + 1);
        searchRecursive(node.right, depth + 1);
    }

    searchRecursive(root);
    return matches;
}

function benchmarkTreeTraversal() {
    console.log("Starting Tree Traversal benchmark...");
    const startTime = Date.now();

    // Step 1: Build binary tree of depth 15
    console.log("Step 1: Building binary tree (depth 15)...");
    const treeDepth = 15;
    const root = buildBalancedBinaryTree(treeDepth, i => i * 7 % 1000); // Some interesting values

    if (!root) {
        throw new Error("Failed to build tree");
    }

    console.log(`Built tree with depth ${getDepth(root)}`);

    // Step 2: Depth-First Search traversal
    console.log("Step 2: Depth-First Search traversal...");
    const dfsResult = depthFirstSearch(root, (node, depth) => {
        // Simulate some processing during traversal
        node.metadata.lastDfsVisit = Date.now();
    });

    // Step 3: Breadth-First Search traversal
    console.log("Step 3: Breadth-First Search traversal...");
    const bfsResult = breadthFirstSearch(root, (node, depth) => {
        // Simulate some processing during traversal
        node.metadata.lastBfsVisit = Date.now();
    });

    // Step 4: In-Order traversal (should produce sorted sequence if it's a BST)
    console.log("Step 4: In-Order traversal...");
    const inOrderResult = inOrderTraversal(root);

    // Step 5: Tree search operations
    console.log("Step 5: Tree search operations...");

    // Find all leaf nodes
    const leafNodes = findNodesWithCondition(root, (node) => node.isLeaf());

    // Find all nodes with even values
    const evenValueNodes = findNodesWithCondition(root, (node) => node.value % 2 === 0);

    // Find all nodes at specific depths
    const depthThreeNodes = findNodesWithCondition(root, (node, depth) => depth === 3);

    // Step 6: Tree statistics calculation
    console.log("Step 6: Calculating tree statistics...");

    function calculateTreeStats(node) {
        if (!node) return { sum: 0, count: 0, min: Infinity, max: -Infinity, depths: [] };

        const leftStats = calculateTreeStats(node.left);
        const rightStats = calculateTreeStats(node.right);

        return {
            sum: node.value + leftStats.sum + rightStats.sum,
            count: 1 + leftStats.count + rightStats.count,
            min: Math.min(node.value, leftStats.min, rightStats.min),
            max: Math.max(node.value, leftStats.max, rightStats.max),
            depths: [getDepth(node)].concat(leftStats.depths, rightStats.depths)
        };
    }

    const treeStats = calculateTreeStats(root);
    treeStats.average = treeStats.count > 0 ? treeStats.sum / treeStats.count : 0;

    // Step 7: Tree serialization
    console.log("Step 7: Tree serialization...");
    const serialized = serializeTree(root);
    const serializedJson = JSON.stringify(serialized.tree, null, 2);

    // Step 8: Validate traversal results
    console.log("Step 8: Validating results...");
    const dfsLength = dfsResult.result.length;
    const bfsLength = bfsResult.result.length;
    const inOrderLength = inOrderResult.result.length;

    if (dfsLength !== bfsLength || bfsLength !== inOrderLength) {
        console.warn(`Traversal length mismatch: DFS=${dfsLength}, BFS=${bfsLength}, InOrder=${inOrderLength}`);
    }

    // Check if all nodes were visited the same number of times
    const expectedNodeCount = Math.pow(2, treeDepth) - 1;
    if (dfsLength !== expectedNodeCount) {
        console.warn(`Expected ${expectedNodeCount} nodes, but traversed ${dfsLength}`);
    }

    const endTime = Date.now();
    const duration = endTime - startTime;

    console.log("Tree Traversal benchmark completed");
    console.log(`Total duration: ${duration}ms`);
    console.log(`Tree depth: ${getDepth(root)}`);
    console.log(`Nodes visited (DFS): ${dfsResult.stats.nodesVisited}`);
    console.log(`Nodes visited (BFS): ${bfsResult.stats.nodesVisited}`);
    console.log(`Leaf nodes found: ${leafNodes.length}`);
    console.log(`Even value nodes: ${evenValueNodes.length}`);
    console.log(`Nodes at depth 3: ${depthThreeNodes.length}`);
    console.log(`Tree stats: sum=${treeStats.sum}, avg=${Math.round(treeStats.average * 100) / 100}, min=${treeStats.min}, max=${treeStats.max}`);
    console.log(`Serialized JSON size: ${serializedJson.length} characters`);

    return {
        duration,
        treeDepth: getDepth(root),
        nodesProcessed: dfsLength,
        operations: {
            treeNodeCreation: expectedNodeCount,
            dfsTraversal: 1,
            bfsTraversal: 1,
            inOrderTraversal: 1,
            searchOperations: 3,
            serialization: 1
        },
        results: {
            leafNodes: leafNodes.length,
            evenNodes: evenValueNodes.length,
            depthThreeNodes: depthThreeNodes.length,
            treeStats: {
                sum: treeStats.sum,
                count: treeStats.count,
                average: Math.round(treeStats.average * 100) / 100,
                min: treeStats.min,
                max: treeStats.max
            }
        },
        serializedSize: serializedJson.length
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkTreeTraversal();
}

// Export for use in benchmark suite
if (typeof module !== 'undefined') {
    module.exports = benchmarkTreeTraversal;
}
