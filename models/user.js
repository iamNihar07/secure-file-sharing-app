var mongoose = require("mongoose");
var passportLocalMongoose = require("passport-local-mongoose");

var userSchema = new mongoose.Schema({
    actualName: String,
    username: String,
    password: String,
    isAdmin: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: false
    },
    userLimit:{
        type: Number,
        min: 5,
        max: 25,
        default: 10
    },
    currentUsage:{
        type: Number,
        min: 0,
        default: 0
    },
    groups: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Group"
        }
    ]
});

//Authentication
userSchema.plugin(passportLocalMongoose);

var User = mongoose.model("User", userSchema);

module.exports = User;