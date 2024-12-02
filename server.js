import "dotenv/config";
import express from "express";
import bcrypt from "bcrypt";
import fs from "fs";
import users from "./users.js";
import isEmail from "validator/lib/isEmail.js";
import isStrongPassword from "validator/lib/isStrongPassword.js";

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

// Middleware function to validate the email and password for the users/login users/signup POST routes only
app.use((req, res, next) => {
  const { username, password } = req.query;
  if (req.path === "/users/login" || req.path === "/users/signup") {
    if (!username || !password) {
      console.log("Username and password are required");
      res.status(400).json({ error: "Username and password are required" });
    } else if (!isEmail(username)) {
      console.log("Invalid email address");
      res.status(400).json({ error: "Invalid email address" });
    } else if (
      !isStrongPassword(password, {
        minLength: 4,
        minLowercase: 0,
        minUppercase: 0,
        minNumbers: 0,
        minSymbols: 0,
        // returnScore: false,
        // pointsPerUnique: 1,
        // pointsPerRepeat: 0.5,
        // pointsForContainingLower: 10,
        // pointsForContainingUpper: 10,
        // pointsForContainingNumber: 10,
        // pointsForContainingSymbol: 10,
      })
    ) {
      console.log("Password is not strong enough: ", password);
      return res.status(400).json({
        error:
          "Password must be at least 8 characters long, and contain at least one uppercase letter, one lowercase letter, one number, and one special character",
      });
    }
  }
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
app.post("/users/signup", async (req, res) => {
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
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  } else if (users.length === 0) {
    console.log("No users found");
    return res.status(404).json({ error: "No users found" });
  }

  // Find the user in the database
  const user = users.find((user) => user.username === username);

  if (!user) {
    console.log("User not found");
    return res.status(404).json({ error: "User not found" });
  }

  try {
    // Compare the password with the hashed password
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      console.log("Login successful");
      return res.status(200).json({ message: "Login successful" });
    } else {
      console.log("Invalid password");
      return res.status(401).json({ error: "Not authorized!" });
    }
  } catch (error) {
    console.log("Error: ", error.message);
    return res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log("Server is running on port 3000");
});
