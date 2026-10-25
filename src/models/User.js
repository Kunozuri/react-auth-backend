import mongoose from 'mongoose';

// ---------- Validation patterns ----------
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const URL_REGEX = /^https?:\/\/[^\s/$.?#][^\s]*$/i;

const ROLES = ['user', 'admin', 'moderator'];
const STATUSES = ['active', 'suspended', 'pending'];

const userSchema = new mongoose.Schema(
    {
        // ---------- Credentials ----------
        email: {
            type: String,
            required: [true, 'Email is required'],
            unique: true,
            lowercase: true,
            trim: true,
            maxlength: [254, 'Email is too long'],
            match: [EMAIL_REGEX, 'Please provide a valid email address'],
        },
        password: {
            type: String,
            required: [true, 'Password is required'],
            minlength: [8, 'Password must be at least 8 characters'],
            select: false, // never returned in queries unless you use .select('+password')
        },

        // ---------- Access control ----------
        role: {
            type: String,
            enum: {values: ROLES, message: '{VALUE} is not a valid role'},
            default: 'user',
        },
        status: {
            type: String,
            enum: {values: STATUSES, message: '{VALUE} is not a valid status'},
            default: 'active',
        },

        // ---------- Profile ----------
        firstName: {
            type: String,
            required: [true, 'First name is required'],
            trim: true, // removes spaces at both ends BEFORE validation runs
            minlength: [2, 'First name must be at least 2 characters'],
            maxlength: [50, 'First name must be at most 50 characters'],
        },
        lastName: {
            type: String,
            required: [true, 'Last name is required'],
            trim: true,
            minlength: [2, 'Last name must be at least 2 characters'],
            maxlength: [50, 'Last name must be at most 50 characters'],
        },

        // OPTIONAL. Allows an optional + at the start, then digits, spaces and dashes.
        // Deliberately loose: phone formats differ a lot between countries.
        phone: {
            type: String,
            trim: true,
            match: [/^\+?[0-9\s-]{7,20}$/, 'Invalid phone number'],
        },

        // OPTIONAL. A 2-letter country code (ISO 3166-1 alpha-2), e.g. "PH", "US".
        // `uppercase: true` turns "ph" into "PH" before the check runs.
        // The frontend can offer a <select> of countries so people can't mistype it.
        country: {
            type: String,
            trim: true,
            uppercase: true,
            match: [/^[A-Z]{2}$/, 'Country must be a 2-letter code'],
        },

        // WHEN the person accepted the terms. A date is better evidence than a plain
        // true/false. It is NOT marked required here: the controller enforces it for
        // new sign-ups, so older accounts without it don't break.
        termsAcceptedAt: {
            type: Date,
        },

        avatar: {
            type: String,
            trim: true,
            match: [URL_REGEX, 'Avatar must be a valid http(s) URL'],
        },

        // ---------- Verification ----------
        isEmailVerified: {type: Boolean, default: false},
        emailVerificationToken: {type: String, select: false},
        emailVerificationExpires: {type: Date, select: false},

        // ---------- Security ----------
        lastLoginAt: Date,
        passwordChangedAt: Date,
        failedLoginAttempts: {type: Number, default: 0},
        lockUntil: Date,
        passwordResetToken: {type: String, select: false},
        passwordResetExpires: {type: Date, select: false},

        // ---------- Soft delete ----------
        deletedAt: {type: Date, default: null},
    },
    {timestamps: true} // adds createdAt and updatedAt automatically
);

const User = mongoose.model('User', userSchema);

export default User;