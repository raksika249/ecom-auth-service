const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const dynamodb = new AWS.DynamoDB.DocumentClient();

const USERS_TABLE = process.env.USERS_TABLE;
const NOTIFICATION_TABLE = process.env.NOTIFICATION_TABLE;

exports.handler = async (event) => {
  try {
    const { email, password, name } = JSON.parse(event.body || '{}');

    if (!email || !password || !name) {
      return response(400, 'Name, email, and password are required');
    }

    // 🔍 Check existing user
    const existingUser = await dynamodb.get({
      TableName: USERS_TABLE,
      Key: { email }
    }).promise();

    if (existingUser.Item) {
      return response(409, 'Email already registered');
    }

    // 🔐 Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 🆕 Generate userId
    const userId = uuidv4();

    // 🧾 Save user (CRITICAL)
    await dynamodb.put({
      TableName: USERS_TABLE,
      Item: {
        email,
        userId,
        name,
        password: hashedPassword,
        role: "user",
        createdAt: new Date().toISOString()
      }
    }).promise();

    // 🔔 OPTIONAL notification (NON-BLOCKING)
    try {
      await dynamodb.put({
        TableName: NOTIFICATION_TABLE,
        Item: {
          notificationId: uuidv4(),
          userId,
          email,
          message: "Welcome! Your account has been created successfully 🎉",
          isRead: false,
          createdAt: new Date().toISOString()
        }
      }).promise();
    } catch (notifyErr) {
      console.warn("Notification insert failed (ignored):", notifyErr.message);
    }

    // ✅ ALWAYS succeed if user is created
    return response(201, 'User registered successfully');

  } catch (err) {
    console.error("Signup failed:", err);
    return response(500, 'Internal server error');
  }
};

const response = (statusCode, message) => ({
  statusCode,
  headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "OPTIONS,POST"
  },
  body: JSON.stringify({ message })
});