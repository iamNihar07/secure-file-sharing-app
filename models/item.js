var mongoose = require("mongoose");
var uniqueValidator = require('mongoose-unique-validator');

var itemSchema = new mongoose.Schema({
    name: {
        type: String,
        unique: true
    },
    url: String,
    mimeType: String,
    fileName: String,
    key: String,
    size: Number,
    creator: {
        id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
        },
        username: String
    },
    description: String,
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastAccess: {
        type: Date
    },
    groups: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Group"
        }
    ]
});

itemSchema.plugin(uniqueValidator);
var Item = mongoose.model("Item", itemSchema);

module.exports = Item;