// Macro-Benchmark 1: JSON Data Transformation
// Tests JSON parsing, array/object manipulation, map/filter/reduce, and serialization

function generateLargeDataset() {
    const data = {
        users: [],
        products: [],
        orders: [],
        metadata: {
            generated_at: "2024-01-01T00:00:00Z",
            version: "1.0.0",
            record_count: 1000
        }
    };

    // Generate 1000 user records
    for (let i = 0; i < 1000; i++) {
        data.users.push({
            id: i + 1,
            name: `User ${i + 1}`,
            email: `user${i + 1}@example.com`,
            age: 18 + (i % 50),
            active: i % 3 !== 0,
            balance: Math.floor(Math.random() * 10000) / 100,
            tags: [`tag${i % 10}`, `category${i % 5}`],
            profile: {
                avatar: `https://example.com/avatar/${i + 1}.jpg`,
                bio: `This is user ${i + 1}'s bio`,
                preferences: {
                    theme: i % 2 === 0 ? "dark" : "light",
                    notifications: i % 4 !== 0
                }
            }
        });
    }

    // Generate 500 product records
    for (let i = 0; i < 500; i++) {
        data.products.push({
            id: i + 1,
            name: `Product ${i + 1}`,
            price: Math.floor(Math.random() * 50000) / 100,
            category: `Category ${i % 10}`,
            available: i % 5 !== 0,
            rating: Math.floor(Math.random() * 50) / 10,
            tags: [`tag${i % 8}`, `feature${i % 6}`]
        });
    }

    // Generate 2000 order records
    for (let i = 0; i < 2000; i++) {
        data.orders.push({
            id: i + 1,
            user_id: Math.floor(Math.random() * 1000) + 1,
            product_id: Math.floor(Math.random() * 500) + 1,
            quantity: Math.floor(Math.random() * 5) + 1,
            status: ["pending", "shipped", "delivered", "cancelled"][i % 4],
            created_at: `2024-${String(Math.floor(i / 100) + 1).padStart(2, '0')}-${String((i % 30) + 1).padStart(2, '0')}T00:00:00Z`
        });
    }

    return data;
}

function benchmarkJsonTransformation() {
    console.log("Starting JSON Data Transformation benchmark...");
    const startTime = Date.now();

    // Step 1: Generate large dataset (simulates JSON.parse of large data)
    console.log("Step 1: Generating dataset...");
    const data = generateLargeDataset();

    // Step 2: JSON round-trip (serialize then parse)
    console.log("Step 2: JSON serialization round-trip...");
    const jsonString = JSON.stringify(data);
    const parsedData = JSON.parse(jsonString);

    // Step 3: Complex data transformations using map/filter/reduce
    console.log("Step 3: Data transformations...");

    // Transform users: filter active users, calculate stats
    const activeUsers = parsedData.users
        .filter(user => user.active)
        .map(user => ({
            id: user.id,
            name: user.name,
            email: user.email,
            age: user.age,
            balance: user.balance,
            tier: user.balance > 500 ? "premium" : user.balance > 100 ? "standard" : "basic"
        }));

    // Aggregate user statistics
    const userStats = parsedData.users.reduce((stats, user) => {
        stats.totalUsers++;
        stats.activeUsers += user.active ? 1 : 0;
        stats.totalBalance += user.balance;
        stats.avgAge = (stats.avgAge * (stats.totalUsers - 1) + user.age) / stats.totalUsers;

        const ageGroup = user.age < 30 ? "young" : user.age < 50 ? "middle" : "senior";
        stats.ageGroups[ageGroup] = (stats.ageGroups[ageGroup] || 0) + 1;

        return stats;
    }, {
        totalUsers: 0,
        activeUsers: 0,
        totalBalance: 0,
        avgAge: 0,
        ageGroups: {}
    });

    // Transform products: calculate category summaries
    const categoryStats = parsedData.products.reduce((stats, product) => {
        if (!stats[product.category]) {
            stats[product.category] = {
                count: 0,
                totalPrice: 0,
                avgRating: 0,
                available: 0
            };
        }
        const cat = stats[product.category];
        cat.count++;
        cat.totalPrice += product.price;
        cat.avgRating = (cat.avgRating * (cat.count - 1) + product.rating) / cat.count;
        cat.available += product.available ? 1 : 0;
        return stats;
    }, {});

    // Transform orders: calculate order statistics by status
    const orderStats = parsedData.orders.reduce((stats, order) => {
        if (!stats[order.status]) {
            stats[order.status] = { count: 0, totalQuantity: 0 };
        }
        stats[order.status].count++;
        stats[order.status].totalQuantity += order.quantity;
        return stats;
    }, {});

    // Step 4: Complex joins (simulate database-style operations)
    console.log("Step 4: Data joins...");
    const enrichedOrders = parsedData.orders
        .filter(order => order.status === "delivered")
        .map(order => {
            const user = parsedData.users.find(u => u.id === order.user_id);
            const product = parsedData.products.find(p => p.id === order.product_id);
            return {
                orderId: order.id,
                userName: user ? user.name : "Unknown",
                userEmail: user ? user.email : "unknown@example.com",
                productName: product ? product.name : "Unknown Product",
                productPrice: product ? product.price : 0,
                quantity: order.quantity,
                totalValue: product ? product.price * order.quantity : 0,
                createdAt: order.created_at
            };
        });

    // Step 5: Final aggregation and sorting
    console.log("Step 5: Final aggregation...");
    const topCustomers = enrichedOrders
        .reduce((customers, order) => {
            if (!customers[order.userEmail]) {
                customers[order.userEmail] = {
                    name: order.userName,
                    email: order.userEmail,
                    totalOrders: 0,
                    totalValue: 0
                };
            }
            customers[order.userEmail].totalOrders++;
            customers[order.userEmail].totalValue += order.totalValue;
            return customers;
        }, {})

    const customerList = Object.values(topCustomers)
        .sort((a, b) => b.totalValue - a.totalValue)
        .slice(0, 10);

    // Step 6: Generate final report
    const report = {
        generatedAt: new Date().toISOString(),
        summary: {
            totalUsers: userStats.totalUsers,
            activeUsers: userStats.activeUsers,
            avgAge: Math.round(userStats.avgAge * 100) / 100,
            totalBalance: Math.round(userStats.totalBalance * 100) / 100
        },
        categoryStats,
        orderStats,
        topCustomers: customerList,
        dataSize: {
            originalJson: jsonString.length,
            users: parsedData.users.length,
            products: parsedData.products.length,
            orders: parsedData.orders.length,
            deliveredOrders: enrichedOrders.length
        }
    };

    // Step 7: Final JSON serialization
    console.log("Step 6: Final serialization...");
    const reportJson = JSON.stringify(report, null, 2);

    const endTime = Date.now();
    const duration = endTime - startTime;

    console.log("JSON Data Transformation benchmark completed");
    console.log(`Total duration: ${duration}ms`);
    console.log(`Processed ${parsedData.users.length} users, ${parsedData.products.length} products, ${parsedData.orders.length} orders`);
    console.log(`Generated ${enrichedOrders.length} enriched orders`);
    console.log(`Final report size: ${reportJson.length} characters`);
    console.log(`Top customer: ${customerList[0] ? customerList[0].name : 'None'} (${customerList[0] ? customerList[0].totalValue : 0} total value)`);

    return {
        duration,
        operations: {
            jsonStringify: 1,
            jsonParse: 1,
            arrayMap: 4,
            arrayFilter: 3,
            arrayReduce: 4,
            arrayFind: enrichedOrders.length * 2,
            arraySort: 1,
            arraySlice: 1
        },
        dataSize: report.dataSize
    };
}

// Run the benchmark if this file is executed directly
if (typeof require !== 'undefined' && require.main === module) {
    benchmarkJsonTransformation();
}