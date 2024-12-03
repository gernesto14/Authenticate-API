import "dotenv/config";
import express from "express";
import bcrypt from "bcrypt";
import fs from "fs";
import users from "./users.js";
import isEmail from "validator/lib/isEmail.js";
import isStrongPassword from "validator/lib/isStrongPassword.js";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT;
const saltRounds = parseInt(process.env.SALT_ROUNDS);

const jwtSecret = process.env.JWT_SECRET;
const jwtExpireIn = process.env.JWT_EXPIRES_IN;

// Middleware function to log the request method and path, and the time it was made, also the source IP address
app.use((req, res, next) => {
  console.log(
    `Request method: ${req.method}, Path: ${
      req.path
    }, Time: ${new Date()}, IP: ${req.ip}`
  );
  next();
});

// Middleware function to validate the email and password for the users/login users/signup  routes only handles POST requests
function validateEmailPassword(req, res, next) {
  const { username, password } = req.query;

  if (!username || !password) {
    console.log("Username and password are required");
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  } else if (!isEmail(username)) {
    console.log("Invalid email address");
    return res.status(400).json({ error: "Invalid email address" });
  } else if (
    !isStrongPassword(password, {
      minLength: 4,
      minLowercase: 0,
      minUppercase: 0,
      minNumbers: 0,
      minSymbols: 0,
    })
  ) {
    console.log("Password is not strong enough: ", password);
    return res.status(400).json({
      error: "Password must be at least 4 characters long.",
    });
  }

  next();
}

// Middleware function to verify the JWT token
function verifyAuthToken(req, res, next) {
  // Check if the token is present
  const token = req.headers.authorization;

  if (!token) {
    console.log("No JWT provided");
    return res
      .status(403)
      .send({ message: "Authentication failed! Please try again :(" });
  }

  // console.log("Auth Token: ", req.headers.authorization.split(" ")[1]);
  const authToken = token.split(" ")[1];

  // verify the token
  jwt.verify(authToken, jwtSecret, function (err, decoded) {
    if (err) {
      console.log("JWT token: ", token);
      console.log("Invalid JWT token");
      return res
        .status(401)
        .send({ message: "Authentication failed! Please try again :(" });
    }

    // create a nice log for the token expiration to be displayed in the console like this: Token expires in: hh:mm:ss
    const expiryTime = new Date(decoded.exp * 1000);
    const currentTime = new Date();
    const timeLeft = expiryTime - currentTime;
    const hours = Math.floor((timeLeft / (1000 * 60 * 60)) % 24);
    const minutes = Math.floor((timeLeft / 1000 / 60) % 60);
    const seconds = Math.floor((timeLeft / 1000) % 60);
    console.log( `Token expires in: ${hours}:${minutes}:${seconds}`);


    next();
  });
}

// allow app to use json
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World");
});

// Get all users
app.get("/users", verifyAuthToken, (req, res) => {
  // console.log(users);
  const { username, password } = users;

  res.json(users);
});

// Create a new user
app.post("/users/signup", validateEmailPassword, async (req, res) => {
  const { username, password } = req.query;

  // find if the user already exists
  const userExists = users.find((user) => user.username === username);
  if (userExists) {
    console.log("User already exists");
    return res.status(400).json({ error: "User already exists" });
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
    return res.status(500).json({ error: error.message });
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
      // Create a JWT token
      const token = jwt.sign({ id: user._id }, jwtSecret, {
        expiresIn: jwtExpireIn, // expires in 24 hours
      });

      console.log("Login successful");
      console.log("Token: ", token);
      // return the information including token as JSON
      return res
        .status(200)
        .send({ message: "Successfully logged-in!", token });
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
