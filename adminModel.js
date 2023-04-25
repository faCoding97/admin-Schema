import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const adminSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50,
    },
    lastName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        validate(value) {
            if (!validator.isEmail(value)) {
                throw new Error("Invalid email address");
            }
        },
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        trim: true,
        validate(value) {
            if (value.toLowerCase().includes("password")) {
                throw new Error('Password should not contain "password"');
            }
        },
    },
    confirmPassword: {
        type: String,
        required: true,
        validate(value) {
            if (value !== this.password) {
                throw new Error("Passwords do not match");
            }
        },
    },
    dob: {
        type: Date,
        required: true,
    },
    gender: {
        type: String,
        enum: ["Male", "Female", "Other"],
        required: true,
    },
    phoneNumber: {
        type: String,
        required: true,
        validate: {
            validator: function (val) {
                return /^\d{11}$/.test(val);
            },
            message: "Phone number should be a 11-digit number",
        },
    },
    address: {
        type: String,
        required: true,
    },
    profilePicture: {
        type: String,
        required: false,
    },
    securityQuestions: {
        question1: {
            type: String,
            required: true,
        },
        answer1: {
            type: String,
            required: true,
        },
        question2: {
            type: String,
            required: true,
        },
        answer2: {
            type: String,
            required: true,
        },
    },
    isAdmin: {
        type: Boolean,
        default: true,
    },
    tokens: [
        {
            token: {
                type: String,
                required: true,
            },
        },
    ],
});

// Hash the password before saving the admin
adminSchema.pre("save", async function (next) {
    const admin = this;
    if (admin.isModified("password")) {
        admin.password = await bcrypt.hash(admin.password, 8);
    }
    next();
});

// Generate auth token for admin
adminSchema.methods.generateAuthToken = async function () {
    const admin = this;
    const token = jwt.sign({ _id: admin._id.toString() }, process.env.JWT_SECRET);
    admin.tokens = admin.tokens.concat({ token });
    await admin.save();
    return token;
};

// Check password for login
adminSchema.methods.checkPassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

// Remove sensitive data before sending the admin object
adminSchema.methods.toJSON = function () {
    const admin = this;
    const adminObject = admin.toObject();

    delete adminObject.password;
    delete adminObject.confirmPassword;
    delete adminObject.tokens;

    return adminObject;
};

// Find admin by email and password
adminSchema.statics.findByCredentials = async (email, password) => {
    const admin = await Admin.findOne({ email });
    if (!admin) {
        throw new Error("Invalid login credentials");
    }
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
        throw new Error("Invalid login credentials");
    }
    return admin;
};

const Admin = mongoose.model("Admin", adminSchema);

module.exports = Admin;
