const request = require('supertest');
const mongoose = require('mongoose');

// Set test DB URI before requiring app
process.env.MONGO_URI = 'mongodb+srv://rizwanikhan63:root@cluster0.n0mstat.mongodb.net/authdb?retryWrites=true&w=majority&appName=Cluster0';
const app = require('../../src/app'); 

let server;
let accessToken;
let refreshToken;

beforeAll(async () => {
  // start server on a random free port
  server = app.listen(0);
  
  // wait until mongoose is connected
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  }
});

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
  if (server) server.close();
});

describe('Auth Service', () => {
  const userPayload = {
    email: 'test@example.com',
    password: 'secret123',
    name: 'Test User',
  };

  test('Register a new user', async () => {
    const res = await request(server)
      .post('/api/v1/auth/register')
      .send(userPayload);

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.user.email).toBe(userPayload.email);
  });

  test('Fail to register with existing email', async () => {
    const res = await request(server)
      .post('/api/v1/auth/register')
      .send(userPayload);

    expect(res.status).toBe(409);
    expect(res.body.success).toBe(false);
  });

  test('Login with correct credentials', async () => {
    const res = await request(server)
      .post('/api/v1/auth/login')
      .send({
        email: userPayload.email,
        password: userPayload.password,
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    accessToken = res.body.data.accessToken;
    refreshToken = res.body.data.refreshToken;
  });

  test('Fail login with wrong password', async () => {
    const res = await request(server)
      .post('/api/v1/auth/login')
      .send({
        email: userPayload.email,
        password: 'wrongpass',
      });

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  test('Refresh token should issue new tokens', async () => {
    const res = await request(server)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    accessToken = res.body.data.accessToken;
    refreshToken = res.body.data.refreshToken;
  });

  test('Protected /me route with valid token', async () => {
    const res = await request(server)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.email).toBe(userPayload.email);
  });

  test('Protected /me route with invalid token', async () => {
    const res = await request(server)
      .get('/api/v1/auth/me')
      .set('Authorization', 'Bearer invalidtoken');

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });
});
