const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const dynamodb = new AWS.DynamoDB.DocumentClient();

const USERS_TABLE = process.env.USERS_TABLE;
const JWT_SECRET = process.env.JWT_SECRET;
const NOTIFICATIONS_TABLE = process.env.NOTIFICATIONS_TABLE;

exports.handler = async (event) => {
  try {
    const body = JSON.parse(event.body || "{}");
    const { email, password } = body;

    if (!email || !password) {
      return response(400, "Email and password are required");
    }

    // 🔍 Get user
    const result = await dynamodb.get({
      TableName: USERS_TABLE,
      Key: { email }
    }).promise();

    if (!result.Item) {
      return response(404, "User not found");
    }

    // 🔐 Validate password
    const isValid = await bcrypt.compare(password, result.Item.password);
    if (!isValid) {
      return response(401, "Invalid credentials");
    }

    // 🎟️ Generate JWT
    const token = jwt.sign(
      {
        email: result.Item.email,
        role: result.Item.role
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // 🔔 Save notification (backend)
    try {
      await dynamodb.put({
        TableName: NOTIFICATIONS_TABLE,
        Item: {
          notificationId: uuidv4(),
          userEmail: email,
          message: "Login successful",
          type: "auth",
          isRead: false,
          createdAt: new Date().toISOString()
        }
      }).promise();
    } catch (notifyErr) {
      console.warn("Notification save failed:", notifyErr.message);
    }

    // 🚀 Send response to frontend
    return {
      statusCode: 200,
      headers: corsHeaders(),
      body: JSON.stringify({
        message: "Login successful",
        token,
        role: result.Item.role,
        notification: {
          message: "Login successful",
          type: "auth"
        }
      })
    };

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return response(500, "Internal server error");
  }
};

const response = (statusCode, message) => ({
  statusCode,
  headers: corsHeaders(),
  body: JSON.stringify({ message })
});

const corsHeaders = () => ({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "OPTIONS,POST"
});
