// Macro-Benchmark 3: Recursive Algorithms
// Tests deep recursion, mathematical computation, and array sorting algorithms

// Fibonacci with memoization for efficiency
function fibonacciMemoized(n, memo = {}) {
    if (n in memo) return memo[n];
    if (n <= 1) return n;

    memo[n] = fibonacciMemoized(n - 1, memo) + fibonacciMemoized(n - 2, memo);
    return memo[n];
}

// Classic recursive Fibonacci (intentionally inefficient for benchmarking)
function fibonacciRecursive(n) {
    if (n <= 1) return n;
    return fibonacciRecursive(n - 1) + fibonacciRecursive(n - 2);
}

// Towers of Hanoi solver
class TowersOfHanoi {
    constructor(numDisks) {
        this.numDisks = numDisks;
        this.moves = [];
        this.stepCount = 0;

        // Initialize towers - tower A starts with all disks
        this.towers = {
            A: [],
            B: [],
            C: []
        };

        // Build initial state (largest disk at bottom)
        for (let i = numDisks; i >= 1; i--) {
            this.towers.A.push(i);
        }
    }

    solve() {
        this.moves = [];
        this.stepCount = 0;
        this.solveTowers(this.numDisks, 'A', 'C', 'B');
        return {
            moves: this.moves,
            stepCount: this.stepCount,
            finalState: JSON.parse(JSON.stringify(this.towers))
        };
    }

    solveTowers(n, source, destination, auxiliary) {
        this.stepCount++;

        if (n === 1) {
            this.moveDisk(source, destination);
            return;
        }

        // Move n-1 disks from source to auxiliary tower
        this.solveTowers(n - 1, source, auxiliary, destination);

        // Move the largest disk from source to destination
        this.moveDisk(source, destination);

        // Move n-1 disks from auxiliary to destination
        this.solveTowers(n - 1, auxiliary, destination, source);
    }

    moveDisk(from, to) {
        const disk = this.towers[from].pop();
        this.towers[to].push(disk);
        this.moves.push({ disk, from, to, state: JSON.parse(JSON.stringify(this.towers)) });
    }

    validateSolution() {
        // Check if all disks are on tower C and in correct order
        if (this.towers.C.length !== this.numDisks) return false;

        for (let i = 0; i < this.towers.C.length - 1; i++) {
            if (this.towers.C[i] <= this.towers.C[i + 1]) return false;
        }

        return this.towers.A.length === 0 && this.towers.B.length === 0;
    }
}

// Quicksort implementation with detailed statistics
class QuickSort {
    constructor(array) {
        this.originalArray = [...array];
        this.array = [...array];
        this.comparisons = 0;
        this.swaps = 0;
        this.recursionDepth = 0;
        this.maxDepth = 0;
    }

    sort() {
        this.comparisons = 0;
        this.swaps = 0;
        this.recursionDepth = 0;
        this.maxDepth = 0;
        this.array = [...this.originalArray];

        this.quicksort(0, this.array.length - 1, 0);

        return {
            sortedArray: [...this.array],
            comparisons: this.comparisons,
            swaps: this.swaps,
            maxDepth: this.maxDepth,
            isSorted: this.validateSort()
        };
    }

    quicksort(low, high, depth) {
        this.recursionDepth = depth;
        this.maxDepth = Math.max(this.maxDepth, depth);

        if (low < high) {
            const pivotIndex = this.partition(low, high);
            this.quicksort(low, pivotIndex - 1, depth + 1);
            this.quicksort(pivotIndex + 1, high, depth + 1);
        }
    }

    partition(low, high) {
        // Use median-of-three for better performance
        const mid = Math.floor((low + high) / 2);
        this.comparisons += 2;

        // Sort low, mid, high
        if (this.array[mid] < this.array[low]) {
            this.swap(low, mid);
        }
        if (this.array[high] < this.array[low]) {
            this.swap(low, high);
        }
        if (this.array[high] < this.array[mid]) {
            this.swap(mid, high);
        }

        // Use middle value as pivot
        this.swap(mid, high - 1);
        const pivot = this.array[high - 1];

        let i = low;
        let j = high - 2;

        while (i <= j) {
            this.comparisons++;
            while (i <= j && this.array[i] < pivot) {
                i++;
                this.comparisons++;
            }

            this.comparisons++;
            while (i <= j && this.array[j] > pivot) {
                j--;
                this.comparisons++;
            }

            if (i < j) {
                this.swap(i, j);
                i++;
                j--;
            }
        }

        this.swap(i, high - 1);
        return i;
    }

    swap(i, j) {
        if (i !== j) {
            const temp = this.array[i];
            this.array[i] = this.array[j];
            this.array[j] = temp;
            this.swaps++;
        }
    }

    validateSort() {
        for (let i = 0; i < this.array.length - 1; i++) {
            if (this.array[i] > this.array[i + 1]) {
                return false;
            }
        }
        return true;
    }
}

// Recursive maze solver (generates and solves a simple maze)
class MazeSolver {
    constructor(width, height) {
        this.width = width;
        this.height = height;
        this.maze = [];
        this.solution = [];
        this.visitedCells = 0;
        this.backtrackSteps = 0;
        this.generateMaze();
    }

    generateMaze() {
        // Create maze with walls (1) and paths (0)
        this.maze = Array(this.height).fill().map(() => Array(this.width).fill(1));

        // Create some paths
        for (let y = 1; y < this.height - 1; y += 2) {
            for (let x = 1; x < this.width - 1; x += 2) {
                this.maze[y][x] = 0; // Path

                // Randomly create connections
                if (Math.random() > 0.3 && x + 2 < this.width - 1) {
                    this.maze[y][x + 1] = 0;
                }
                if (Math.random() > 0.3 && y + 2 < this.height - 1) {
                    this.maze[y + 1][x] = 0;
                }
            }
        }

        // Ensure start and end are paths
        this.maze[1][1] = 0; // Start
        this.maze[this.height - 2][this.width - 2] = 0; // End
    }

    solveMaze() {
        this.solution = [];
        this.visitedCells = 0;
        this.backtrackSteps = 0;

        const visited = Array(this.height).fill().map(() => Array(this.width).fill(false));
        const path = [];

        const found = this.findPath(1, 1, this.width - 2, this.height - 2, visited, path);

        return {
            solutionFound: found,
            path: [...this.solution],
            visitedCells: this.visitedCells,
            backtrackSteps: this.backtrackSteps,
            pathLength: this.solution.length
        };
    }

    findPath(x, y, endX, endY, visited, path) {
        // Check bounds and walls
        if (x < 0 || x >= this.width || y < 0 || y >= this.height) return false;
        if (this.maze[y][x] === 1 || visited[y][x]) return false;

        // Mark as visited
        visited[y][x] = true;
        path.push({ x, y });
        this.visitedCells++;

        // Check if we reached the destination
        if (x === endX && y === endY) {
            this.solution = [...path];
            return true;
        }

        // Try all four directions
        const directions = [
            { dx: 1, dy: 0 },   // Right
            { dx: 0, dy: 1 },   // Down
            { dx: -1, dy: 0 },  // Left
            { dx: 0, dy: -1 }   // Up
        ];

        for (const dir of directions) {
            if (this.findPath(x + dir.dx, y + dir.dy, endX, endY, visited, path)) {
                return true;
            }
        }

        // Backtrack
        path.pop();
        this.backtrackSteps++;
        return false;
    }
}

function generateRandomArray(size, min = 1, max = 10000) {
    const array = [];
    for (let i = 0; i < size; i++) {
        array.push(Math.floor(Math.random() * (max - min + 1)) + min);
    }
    return array;
}

function benchmarkRecursiveAlgorithms() {
    console.log("Starting Recursive Algorithms benchmark...");
    const startTime = Date.now();

    const results = {};

    // Test 1: Fibonacci calculations
    console.log("Step 1: Fibonacci calculations...");
    const fibStart = Date.now();

    // Calculate Fibonacci(35) with memoization (efficient)
    const fib35Memo = fibonacciMemoized(35);
    const fib35MemoTime = Date.now() - fibStart;

    // Calculate smaller Fibonacci recursively (to avoid timeout)
    const fibRecursiveStart = Date.now();
    const fib30Recursive = fibonacciRecursive(30);
    const fib30RecursiveTime = Date.now() - fibRecursiveStart;

    results.fibonacci = {
        memoized: { value: fib35Memo, time: fib35MemoTime, input: 35 },
        recursive: { value: fib30Recursive, time: fib30RecursiveTime, input: 30 }
    };

    // Test 2: Towers of Hanoi
    console.log("Step 2: Towers of Hanoi...");
    const hanoiStart = Date.now();
    const hanoi = new TowersOfHanoi(10); // 10 disks
    const hanoiResult = hanoi.solve();
    const hanoiValid = hanoi.validateSolution();
    const hanoiTime = Date.now() - hanoiStart;

    results.hanoi = {
        disks: 10,
        moves: hanoiResult.moves.length,
        steps: hanoiResult.stepCount,
        time: hanoiTime,
        valid: hanoiValid,
        expectedMoves: Math.pow(2, 10) - 1
    };

    // Test 3: Quicksort on large array
    console.log("Step 3: Quicksort algorithm...");
    const sortStart = Date.now();
    const arraySize = 100000;
    const randomArray = generateRandomArray(arraySize);
    const quickSort = new QuickSort(randomArray);
    const sortResult = quickSort.sort();
    const sortTime = Date.now() - sortStart;

    results.quicksort = {
        arraySize: arraySize,
        comparisons: sortResult.comparisons,
        swaps: sortResult.swaps,
        maxDepth: sortResult.maxDepth,
        time: sortTime,
        isSorted: sortResult.isSorted
    };

    // Test 4: Maze solving
    console.log("Step 4: Recursive maze solving...");
    const mazeStart = Date.now();
    const maze = new MazeSolver(21, 21); // 21x21 maze
    const mazeResult = maze.solveMaze();
    const mazeTime = Date.now() - mazeStart;

    results.maze = {
        dimensions: { width: 21, height: 21 },
        solutionFound: mazeResult.solutionFound,
        pathLength: mazeResult.pathLength,
        visitedCells: mazeResult.visitedCells,
        backtrackSteps: mazeResult.backtrackSteps,
        time: mazeTime
    };

    // Test 5: Recursive factorial and combinations
    console.log("Step 5: Mathematical recursive functions...");
    const mathStart = Date.now();

    function factorial(n) {
        if (n <= 1) return 1;
        return n * factorial(n - 1);
    }

    function combinations(n, k) {
        if (k === 0 || k === n) return 1;
        if (k === 1 || k === n - 1) return n;
        return combinations(n - 1, k - 1) + combinations(n - 1, k);
    }

    const fact20 = factorial(20);
    const comb15_7 = combinations(15, 7);
    const mathTime = Date.now() - mathStart;

    results.mathematical = {
        factorial20: fact20,
        combinations15_7: comb15_7,
        time: mathTime
    };

    const endTime = Date.now();
    const duration = endTime - startTime;

    console.log("Recursive Algorithms benchmark completed");
    console.log(`Total duration: ${duration}ms`);
    console.log(`Fibonacci(35) memoized: ${results.fibonacci.memoized.value} (${results.fibonacci.memoized.time}ms)`);
    console.log(`Fibonacci(30) recursive: ${results.fibonacci.recursive.value} (${results.fibonacci.recursive.time}ms)`);
    console.log(`Hanoi (10 disks): ${results.hanoi.moves} moves in ${results.hanoi.time}ms (valid: ${results.hanoi.valid})`);
    console.log(`Quicksort (${arraySize} elements): ${results.quicksort.comparisons} comparisons, ${results.quicksort.swaps} swaps (${results.quicksort.time}ms)`);
    console.log(`Maze solving: path length ${results.maze.pathLength}, visited ${results.maze.visitedCells} cells (${results.maze.time}ms)`);
    console.log(`Mathematical: 20! = ${results.mathematical.factorial20}, C(15,7) = ${results.mathematical.combinations15_7}`);

    return {
        duration,
        operations: {
            fibonacciMemoized: 1,
            fibonacciRecursive: 1,
            towersOfHanoi: 1,
            quicksort: 1,
            mazeSolver: 1,
            factorial: 1,
            combinations: 1
        },
        results: results
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkRecursiveAlgorithms();
}