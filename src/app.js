// app.js
import express from 'express';
import userAuthRouter from './routes/auth.routes.js';
import errorMiddleware from './middlewares/error.middleware.js';

import cookieParser from 'cookie-parser';

const app = express();

// express.json() reads JSON request bodies into req.body.
// cookieParser() does the same for cookies and puts them in req.cookies.
// Without it, req.cookies is undefined and the refresh token can't be read.
// IMPORTANT: this must come BEFORE your routes, because Express runs
// middleware in the order it is written.
app.use(express.json());
app.use(cookieParser());

app.use('/api/auth', userAuthRouter);

app.use(errorMiddleware);

app.get('/', (req, res) => {
    res.send('welcome to the app api');
});

export default app;