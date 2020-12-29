var mongoose = require("mongoose");

var groupSchema = new mongoose.Schema({
    groupName: String,
    isActive: {
        type: Boolean,
        default: false
    },
    groupLimit: {
        type:Number,
        default: 25,
        min:10
    },
    currentUsage: {
        type: Number,
        default: 0,
        min: 0
    }
});


var Group = mongoose.model("Group", groupSchema);

module.exports = Group;