// bcryptjs: a library that turns a plain password into a one-way "hash".
// We never store the real password, only the hash, so a database leak doesn't expose passwords.
import bcrypt from 'bcryptjs';

// Our models. In ES modules the ".js" at the end is REQUIRED, otherwise Node can't find the file.
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';

// NEW: the two helpers this refactor is about.
// ApiError     -> replaces the 3 lines (new Error + statusCode + throw) with one.
// asyncHandler -> replaces the try/catch/next(error) that was repeated in every controller.
import ApiError from '../utils/ApiError.js';
import asyncHandler from '../utils/asyncHandler.js';

import {
    signAccessToken,       // makes the short-lived (15 min) JWT
    createRefreshToken,    // makes the long random refresh token AND saves its hash in MongoDB
    hashToken,             // hashes a token so we can look it up in MongoDB
    refreshCookieOptions,  // httpOnly / secure / sameSite / maxAge for the refresh cookie
    clearCookieOptions,    // the same options without maxAge, used to delete the cookie
} from '../utils/tokens.js';

// A named constant instead of a "magic number" scattered in the code. Easy to change in one place.
const MIN_PASSWORD_LENGTH = 8;

// Helper used by signUp, signIn and refresh.
// It creates BOTH tokens, puts the refresh token in a cookie, and returns the access token.
// It is NOT a route handler, so it does not need asyncHandler. If it throws, the error travels up
// to whichever wrapped controller called it.
const issueTokens = async (res, user) => {
    // Short-lived JWT. The server does not store it, it only verifies it on each request.
    const accessToken = signAccessToken(user);

    // Long random string, valid for 7 days. Its HASH is saved in the database,
    // which is what lets us revoke it when the user signs out.
    const refreshToken = await createRefreshToken(user._id);

    // The refresh token goes in an httpOnly cookie. JavaScript on the page can't read it, so XSS can't steal it.
    res.cookie('refreshToken', refreshToken, refreshCookieOptions);

    return accessToken;
};

// ---------------------------------------------------------------------------
// HOW EACH CONTROLLER CHANGED
//
// BEFORE:  export const signUp = async (req, res, next) => {
//              try {
//                  ...
//                  const error = new Error('Email already in use');
//                  error.statusCode = 409;
//                  throw error;
//                  ...
//              } catch (error) {
//                  next(error);
//              }
//          };
//
// AFTER:   export const signUp = asyncHandler(async (req, res) => {
//              ...
//              throw new ApiError(409, 'Email already in use');
//              ...
//          });
//
// - No try/catch: asyncHandler catches anything thrown and calls next(error) for us.
// - No `next` parameter: we never call it by hand anymore.
// - `throw new ApiError(status, message)` is the whole error in one line.
// ---------------------------------------------------------------------------

// ============================================================================
// sign-up.controller.js - the updated signUp, with more fields.
// ============================================================================
//
// This REPLACES the signUp function in your auth.controller.js. The imports at
// the top of that file stay the same (asyncHandler, ApiError, User, bcrypt,
// issueTokens, MIN_PASSWORD_LENGTH).
//
// WHAT CHANGED
//   - `name` is now `firstName` + `lastName`.
//   - New optional fields: phone, country.
//   - New required check: acceptedTerms must be exactly `true`.
//   - There is NO confirmPassword here on purpose. It's only a typo guard for
//     the person typing, so the frontend checks it and never sends it.
//
// WHAT DID NOT CHANGE
//   The security approach is the same as before: take only the fields we
//   accept, check that they are plain strings, check the password length
//   before hashing, hash it, and send back the user without the hash.
// ============================================================================

// ---------------------------------------------------------------------------
// SIGN UP
// ---------------------------------------------------------------------------
export const signUp = asyncHandler(async (req, res) => {
    // Take ONLY these fields. If we spread req.body into User.create(),
    // a user could send { "role": "admin" } and make themselves an admin.
    const { firstName, lastName, email, password, phone, country, acceptedTerms } = req.body;

    // typeof check on the REQUIRED text fields: makes sure they are plain strings.
    // Without it, someone could send { "$gt": "" } as the email and trick the
    // query below (NoSQL injection).
    if (
        typeof firstName !== 'string' ||
        typeof lastName !== 'string' ||
        typeof email !== 'string' ||
        typeof password !== 'string'
    ) {
        throw new ApiError(400, 'First name, last name, email and password are required');
    }

    // The OPTIONAL fields may be missing (undefined), but if they ARE sent they
    // must be strings too, for the same reason.
    if (
        (phone !== undefined && typeof phone !== 'string') ||
        (country !== undefined && typeof country !== 'string')
    ) {
        throw new ApiError(400, 'Invalid phone or country');
    }

    // `!== true` is strict on purpose: the string "true", the number 1 or
    // anything else does NOT count. Only a real boolean true passes.
    if (acceptedTerms !== true) {
        throw new ApiError(400, 'You must accept the terms to create an account');
    }

    // Check the length BEFORE hashing. A bcrypt hash is always 60 characters, so
    // the model's minlength rule would always pass after hashing, even for a
    // 1-character password.
    if (password.length < MIN_PASSWORD_LENGTH) {
        throw new ApiError(400, `Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
    }

    // trim() removes spaces at the ends, toLowerCase() makes "A@B.com" and
    // "a@b.com" the same.
    const normalizedEmail = email.trim().toLowerCase();

    // findOne returns the user document, or null if nobody has this email.
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
        throw new ApiError(409, 'Email already in use'); // 409 = Conflict
    }

    // The salt is random data mixed in so two users with the same password get
    // different hashes. 10 is the cost: higher = safer but slower.
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Mongoose runs the model's validation first (name lengths, phone format...).
    // If it fails it throws a ValidationError, and error.middleware.js turns that
    // into a 400 response with the validation messages.
    const newUser = await User.create({
        firstName,
        lastName, // the schema's `trim: true` cleans the spaces
        email: normalizedEmail,
        password: hashedPassword,

        // Optional fields: `phone?.trim()` is undefined when phone is missing.
        // `|| undefined` also turns an empty string "" into undefined, so we
        // never store "" (which would fail the format rules in the model).
        phone: phone?.trim() || undefined,
        country: country?.trim() || undefined,

        // We store WHEN they accepted, not just that they did.
        termsAcceptedAt: new Date(),
    });

    // The new user is signed in right away: access token returned, refresh
    // cookie set on `res`.
    const accessToken = await issueTokens(res, newUser);

    // create() returns the document WITH the password hash (select: false only
    // hides it on queries), so convert to a plain object and remove it.
    const userData = newUser.toObject();
    delete userData.password;

    // 201 = Created. The refresh token is NOT in the body, it travels in the
    // httpOnly cookie only.
    res.status(201).json({
        success: true,
        message: 'User created successfully',
        data: {
            accessToken,
            user: userData,
        },
    });
});

// ---------------------------------------------------------------------------
// SIGN IN
// ---------------------------------------------------------------------------
export const signIn = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (typeof email !== 'string' || typeof password !== 'string') {
        throw new ApiError(400, 'Email and password are required');
    }

    const normalizedEmail = email.trim().toLowerCase();

    // deletedAt: null     -> only match accounts that haven't been soft-deleted.
    // .select('+password') -> the model hides the password by default; "+" includes it this time.
    const user = await User.findOne({ email: normalizedEmail, deletedAt: null }).select('+password');

    // Same message for "no such user" and "wrong password", so an attacker can't discover which emails exist.
    if (!user) {
        throw new ApiError(401, 'Invalid credentials'); // 401 = Unauthorized
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        throw new ApiError(401, 'Invalid credentials');
    }

    // Checked AFTER the password, so only someone who knows the password learns the account is suspended.
    if (user.status === 'suspended') {
        throw new ApiError(403, 'This account has been suspended'); // 403 = Forbidden
    }

    // Changes just that one field, without loading and re-saving the whole document.
    await User.updateOne({ _id: user._id }, { lastLoginAt: new Date() });

    const accessToken = await issueTokens(res, user);

    // The document still carries the password hash (we asked for it with +password), so remove it.
    const userData = user.toObject();
    delete userData.password;

    res.status(200).json({
        success: true,
        message: 'User signed in successfully',
        data: {
            accessToken,
            user: userData,
        },
    });
});

// ---------------------------------------------------------------------------
// SIGN OUT
// POST /api/auth/sign-out
// Signing out = delete the refresh token from the database + clear the cookie.
// ---------------------------------------------------------------------------
export const signOut = asyncHandler(async (req, res) => {
    const token = req.cookies?.refreshToken;

    // No cookie is not an error: the user is already signed out, so the result they wanted is true either way.
    if (typeof token === 'string') {
        await RefreshToken.deleteOne({ tokenHash: hashToken(token) });
    }

    // Must use the same options the cookie was set with (minus maxAge), otherwise the browser may keep it.
    res.clearCookie('refreshToken', clearCookieOptions);

    // NOTE: the current access token still works until its 15 minutes run out.
    res.status(200).json({
        success: true,
        message: 'Signed out successfully',
    });
});

// ---------------------------------------------------------------------------
// REFRESH
// POST /api/auth/refresh
// Called when the access token has expired and the client needs a new one.
// The client sends NO Bearer token here. The refresh token arrives in the cookie.
// ---------------------------------------------------------------------------
export const refresh = asyncHandler(async (req, res) => {
    const token = req.cookies?.refreshToken;

    // Only accept a plain string (cookie-parser can turn some cookie values into objects).
    if (typeof token !== 'string') {
        throw new ApiError(401, 'No refresh token');
    }

    // Find the record AND delete it in one step, so every refresh token can only be used ONCE (rotation).
    const stored = await RefreshToken.findOneAndDelete({ tokenHash: hashToken(token) });

    // Not found (never existed, already used, or signed out), or past its expiry date -> reject.
    if (!stored || stored.expiresAt < new Date()) {
        throw new ApiError(401, 'Invalid or expired refresh token');
    }

    // The user may have been deleted or suspended since they signed in, so check again.
    const user = await User.findOne({ _id: stored.user, deletedAt: null });
    if (!user) {
        throw new ApiError(401, 'User not found');
    }
    if (user.status === 'suspended') {
        throw new ApiError(403, 'This account has been suspended');
    }

    // Fresh pair: a new access token (returned) and a new refresh token (set in the cookie).
    const accessToken = await issueTokens(res, user);

    res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        data: { accessToken },
    });
});

// ---------------------------------------------------------------------------
// GET ME
// GET /api/auth/me
// JUST A TESTER to check that the access token is valid (and to partially get you to a dashboard).
// This is an authentication backend, so profile features live elsewhere.
// ---------------------------------------------------------------------------
// Not async and nothing can fail here, so it needs no asyncHandler.
export const getMe = (req, res) => {
    // req.user was attached by authMiddleware, so we can just send it back
    res.json({ success: true, data: { user: req.user } });
};