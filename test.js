const BASE_URL = "http://localhost:3000";

async function runTests() {
  console.log("Starting JWT Auth Lab Tests...\n");

  try {
    // 1. Register a new user
    console.log("Test 1: Registering a new user...");
    const regRes = await fetch(`${BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "tester",
        password: "password123",
        role: "student"
      })
    });
    const regData = await regRes.json();
    console.log("Response:", regData);

    // 2. Login
    console.log("\nTest 2: Logging in...");
    const loginRes = await fetch(`${BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "tester",
        password: "password123"
      })
    });
    const loginData = await loginRes.json();
    console.log("Response:", loginData);
    const { accessToken, refreshToken } = loginData;

    if (!accessToken) throw new Error("Login failed - no token received");

    // 3. Access Protected Route (Profile)
    console.log("\nTest 3: Accessing protected /profile...");
    const profileRes = await fetch(`${BASE_URL}/profile`, {
      headers: { "Authorization": `Bearer ${accessToken}` }
    });
    const profileData = await profileRes.json();
    console.log("Response:", profileData);

    // 4. Access Admin Route (should fail)
    console.log("\nTest 4: Accessing /admin as student (expected to fail)...");
    const adminRes = await fetch(`${BASE_URL}/admin`, {
      headers: { "Authorization": `Bearer ${accessToken}` }
    });
    const adminData = await adminRes.json();
    console.log("Response (Status " + adminRes.status + "):", adminData);

    // 5. Refresh Token
    console.log("\nTest 5: Refreshing token...");
    const refreshRes = await fetch(`${BASE_URL}/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken })
    });
    const refreshData = await refreshRes.json();
    console.log("Response:", refreshData);
    const newAccessToken = refreshData.accessToken;

    // 6. Logout
    console.log("\nTest 6: Logging out...");
    const logoutRes = await fetch(`${BASE_URL}/logout`, {
      method: "POST",
      headers: { 
        "Authorization": `Bearer ${newAccessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ refreshToken })
    });
    const logoutData = await logoutRes.json();
    console.log("Response:", logoutData);

    // 7. Verify token is blacklisted
    console.log("\nTest 7: Accessing /profile with blacklisted token (expected to fail)...");
    const finalRes = await fetch(`${BASE_URL}/profile`, {
      headers: { "Authorization": `Bearer ${newAccessToken}` }
    });
    const finalData = await finalRes.json();
    console.log("Response (Status " + finalRes.status + "):", finalData);

    console.log("\nAll tests completed!");
  } catch (error) {
    console.error("\nTest failed:", error.message);
    console.log("\nMake sure the server is running with 'npm start' before running tests.");
  }
}

runTests();
