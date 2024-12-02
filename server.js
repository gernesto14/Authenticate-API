import "dotenv/config";
import express from "express";
import bcrypt from "bcrypt";
import fs from "fs";
import users from "./users.js";

const app = express();
const PORT = process.env.PORT;
const saltRounds = parseInt(process.env.SALT_ROUNDS);

// Middleware function to log the request method and path, and the time it was made, also the source IP address
app.use((req, res, next) => {
  console.log(
    `Request method: ${req.method}, Path: ${
      req.path
    }, Time: ${new Date()}, IP: ${req.ip}`
  );
  next();
});

// allow app to use json
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World");
});

// Get all users
app.get("/users", (req, res) => {
  console.log(users);
  const { username, password } = users;
  console.log(typeof username);

  res.json(users);
});

// Create a new user
app.post("/users", async (req, res) => {
  const { username, password } = req.query;

  // find if the user already exists
  const userExists = users.find((user) => user.username === username);
  if (userExists) {
    console.log("User already exists");
    res.status(400).json({ error: "User already exists" });
  }

  try {
    const salt = await bcrypt.genSalt(saltRounds);
    console.log("Salt: ", salt);

    // Hash the password
    const hash = await bcrypt.hash(password, salt);
    console.log("Hash: ", hash);
    console.log("Username: ", username);
    console.log("Password:", password);
    console.log("Salt Rounds: ", saltRounds);

    // Push the new user to the database/file
    users.push({ username, password: hash });

    // Write the updated users array to the file
    fs.writeFileSync(
      "./users.js",
      `const users = ${JSON.stringify(
        users,
        null,
        2
      )};\n\nexport default users;\n`
    );

    res.status(200).json({ message: "User added successfully" });
  } catch (error) {
    console.log("Error: ", error.message);
    res.status(500).json({ error: error.message });
  }
});

// Login a user
app.post("/users/login", async (req, res) => {
  const { username, password } = req.query;

  if (!req.query.username || !req.query.password) {
    console.log("Username and password are required");
    res.status(400).json({ error: "Username and password are required" });
  } else if (users.length === 0) {
    console.log("No users found");
    res.status(404).json({ error: "No users found" });
  }

  // Find the user in the database
  const user = users.find((user) => user.username === username);

  if (!user) {
    console.log("User not found");
    res.status(404).json({ error: "User not found" });
  }
  try {
    // Compare the password with the hashed password
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      console.log("Login successful");
      res.status(200).json({ message: "Login successful" });
    } else {
      console.log("Invalid password");
      res.status(401).json({ error: "Not authorized!" });
    }
  } catch (error) {
    console.log("Error: ", error.message);
    res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log("Server is running on port 3000");
});
