var express                 = require("express"),
    mongoose                = require("mongoose"),
    passport                = require("passport"),
    bodyParser              = require("body-parser"),
    LocalStrategy           = require("passport-local"),
    passportLocalMongoose   = require("passport-local-mongoose"),
    expressSession          = require("express-session"),
    expressSanitizer        = require("express-sanitizer"),
    flash                   = require("connect-flash"),
    methodOverride          = require("method-override"),
    momentJS                = require("moment"),
    multer                  = require('multer');
    fs                      = require('fs'),
    path                    = require('path'),
    uniqueValidator         = require('mongoose-unique-validator'),
    dotenv                  = require('dotenv'),
    cors                    = require('cors'),
    multers3                = require('multer-s3'),
    aws                     = require('aws-sdk');

var env_status = dotenv.config();
var passwords = require("./public/dict/passwords");
const { check, validationResult } = require('express-validator');


//models
var User                    = require("./models/user"),
    Group                   = require("./models/groups"),
    Item                    = require("./models/item");


var url = process.env.DATABASE_URL || "mongodb://localhost/sppp_app" ; 
mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, 'useCreateIndex': true });

var app = express();
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(expressSanitizer()); //always after bodyParser
app.use(methodOverride("_method"));
app.use(flash());
app.use(cors());
app.use(express.static(__dirname + "/public")); //__dirname gets the current directory name

//Authentication code
app.use(expressSession({
    secret: process.env.EXP_SECRET,
    resave: false,
    saveUninitialized: false,
    //expires: new Date(Date.now() + (1800 * 1000))
    //expires: new Date(Date.now() + (600 * 1000)),
    cookie: {
        maxAge: 30* 60 * 1000 //30minutes
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

var fileLimitUpload = 3;

//passing currentUser (either logged in or not) to all pages
//so as to not pass currentUser manually to every ejs template like park index.ejs
function currUser(req,res,next){
    res.locals.currentUser = req.user;
    res.locals.errorMessage = req.flash("error");
    res.locals.successMessage = req.flash("success");
    res.locals.page = "page";
    res.locals.moment = momentJS;
    res.locals.fileLimitSize = fileLimitUpload;
    next();
}
app.use(currUser);

var s3 = new aws.S3({
    accessKeyId: process.env.S3_ACCESS_KEY,
    secretAccessKey: process.env.S3_ACCESS_SECRET
});

function deleteFromS3(key){
    s3.deleteObject({
        Bucket: process.env.AWS_BUCKET,
        Key: key
      },function (err,data){
          if(err){
              console.log(err);
              return;
          }
          //console.log("deleted");
      });
}

// ==========================
//           ROUTES
app.get("/",function(req,res){
    res.render("auth/landing");
});


//============================
//Auth routes

//Show Sign up form
app.get("/register", function(req,res){
    //get all groups from DB
    Group.find({}, function(err,allGroups){
        if(err){
            req.flash("error", "Group not found");
            res.redirect("/home");
        }else{
            res.render("auth/register", {groups: allGroups, page: "register"});
            //redudant to pass currentUser since we already have a function currUser in app.js to eliminate this need
        }
    });
});

//handing user sign up
app.post("/register", [ 
    check('actualName').isLength({min:2}).withMessage('Actual Name must be at least 2 characters long'), 
    check('actualName').isLength({max:80}).withMessage('Actual Name can be at most 80 characters long'), 
    check('username').isLength({min:6}).withMessage('Username must be at least 6 characters long'),
    check('username').isLength({max:16}).withMessage('Username can be at most 16 characters long'),
    check('username').isAscii().withMessage('Username can only contain ASCII characters'),
    check('username').custom(value => !/\s/.test(value)).withMessage('No spaces are allowed in the username'),
    check('password').custom(value => !/\s/.test(value)).withMessage('No spaces are allowed in the password'),
    check('password').isLength({max:20}).withMessage('Password can be atmost 20 characters long'),
    check('password', 'The password must be at least 8 characters long and contain a number')
    .not().isIn(passwords).withMessage('Common words are not accepted as a password')
    .isLength({ min: 8 })
    .matches(/\d/)
], function(req,res){

    if(req.body.password !== req.body.conf_password){
        req.flash("error", "Passwords do not match.");
        res.redirect("/register");
        return;
    }

    var errors = validationResult(req);
    if (!errors.isEmpty()) {
        //console.log(errors.array());
        var error_mssg="";
        errors.array().forEach(function (error){
            error_mssg = error_mssg + error.msg + ". ";
        });
        req.flash("error",error_mssg);
        res.redirect("/register");
        return;
    //return res.status(400).json({ errors: errors.array() });
    }
    //get all groups from DB
    Group.find({}, function(err,allGroups){
        if(err){
            req.flash("error", "Group not found");
            res.redirect("/home");
        }else{
            //Code sanitization - removes any malicious script tags
            req.body.actualName = req.sanitize(req.body.actualName);
            req.body.username = req.sanitize(req.body.username);


            req.body.default = "on";
            var tempUser = {
                actualName: req.body.actualName,
                username: req.body.username,
                groups: []
            };
            allGroups.forEach(function(group){
                if(group.groupName in req.body){
                    tempUser.groups.push(group._id);  
                }
            });

            User.register(new User(tempUser), req.body.password, function(err, addedUser){
                //we do not store direct password in mongoDB, passport local hashes it for us, hence password is not passed on to user body
                // the callback returns an "user", with the given username, and hashed password
                if(err){
                    req.flash("error", err.message);
                    res.redirect("/register");
                }
                else{
                passport.authenticate("local")(req, res, function(){
                    req.flash("success", "Welcome to SPPP, "+addedUser.actualName+"!");
                    res.redirect("/home");
                    
                });
            }});
        }
    });

    
});

//Login Routes
//render login form
app.get("/login", isLoggedOut, function(req,res){
    res.render("auth/login", {page: "login"});
});

//Login logic 
//middleware
app.post("/login", passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login",
    failureFlash: true,
    successFlash: "Welcome to SPPP!"
}), function(req,res){
    //do nothing after redirecting
});

//Logout logic
app.get("/logout", function(req,res){
   req.logout();
   req.flash("success", "Logged Out!");
   res.redirect("/"); 
});


//ITEM ROUTES

//INDEX route - view/show all posts
app.get("/home", isLoggedIn, isActive, function(req,res){
    if(req.user.isAdmin){
        fillAdmin();
    }    
    Item.find().populate("groups").exec(function(err, items){
        if(err){
            req.flash("error", "No items uploaded yet");
            res.redirect("/home");
        }else{
            Group.find({}, function(err,allGroups){
                if(err){
                    req.flash("error", "Groups not found");
                    res.redirect("/");
                    return;
                }else{
                    res.render("main/index", {items: items, groups: allGroups, page: "home"});
                }
            });
            
        }
    });    
});

//CREATE route - add new item to DB
app.post("/home", isLoggedIn, function(req,res){

    var uploadS3 = multer({
        storage: multers3({
            s3: s3,
            acl: 'public-read',
            bucket: process.env.AWS_BUCKET,
            metadata: (req,file,cb) => {
                cb(null, {fieldname: file.fieldname});
            },
            key: (req,file,cb)=>{
                cb(null, Date.now().toString()+'-'+file.originalname);
            }
        }),
        limits: {
            fileSize: fileLimitUpload * Math.pow(1024, 2)
        }
    }).single('userFile');

    uploadS3(req,res, function(err){
        if(err){
            if(err.code === "LIMIT_FILE_SIZE"){
                req.flash("error", "File Size Too Large. Current Item Size Limit is "+fileLimitUpload+" MB.");
                res.redirect("/home/new");
                return;
            }else{
                req.flash("error", "File Upload Error. Try Again");
                res.redirect("/home/new");
                return;
            }
        }

        if(!req.file){
            req.flash("error", "Please select a file.");
            res.redirect("/home/new");
            return;
        }

        var capacity = req.user.currentUsage+Math.ceil(req.file.size/(Math.pow(1024,2)));
        if(capacity > req.user.userLimit){
            deleteFromS3(req.file.key);
            req.flash("error","Cannot upload this item as total storage for "+req.user.username+" is exceeding user limit of "+req.user.userLimit+" MB.");
            res.redirect("/home/new");
            return;
        }else{
            
        }
    
        Group.find({}, function(err, allGroups){
            if(err){
                deleteFromS3(req.file.key);
                req.flash("error","Group not found");
                res.redirect("/home");
            }else{
                if(req.body.name.length<3 || req.body.name.length>68){
                    deleteFromS3(req.file.key);
                    req.flash("error","Item has should be 3-68 characters.");
                    res.redirect("/home/new");
                    return;
                }
                if(req.body.description.length<6 || req.body.name.length>1000){
                    deleteFromS3(req.file.key);
                    req.flash("error","Item description should be 6-1000 characters");
                    res.redirect("/home/new");
                    return;
                }
                
                //Code Sanitization
                req.body.name = req.sanitize(req.body.name);
                req.body.description = req.sanitize(req.body.description);               


                req.body.default="on";
                var newItem = {
                    name: req.body.name,
                    description: req.body.description,
                    lastAccess: new Date(Date.now()),            
                    url: req.file.location,
                    mimeType: req.file.mimetype, 
                    fileName: req.file.originalname,
                    key: req.file.key,
                    size: Math.ceil(req.file.size/Math.pow(1024,2)),
                    creator: {
                        id: req.user._id,
                        username: req.user.username
                    },
                    groups: []
                };
                var flag=true;
                allGroups.forEach(function(group){
                    if(group.groupName in req.body){
                        if(group.currentUsage+1>group.groupLimit){
                            flag=false;
                        }else{
                            group.currentUsage++;
                            group.save();
                            newItem.groups.push(group._id);
                        }  
                    }
                });

                if(newItem.groups.length==0){
                    req.flash("error", "Group Limits exceeded for all selected groups.")
                    res.redirect("/home");
                    return;
                }

                Item.create(newItem, function(err, addedItem){
                    if(err){
                        req.flash("error","Item not created");
                        res.redirect("/home");
                    }else{
                        // allGroups.forEach(function(group){
                        //     if(group.groupName in req.body){
                        //         addedItem.groups.push(group);  
                        //     }
                        // });
                        // addedItem.save();

                        User.findByIdAndUpdate(req.user._id, {$set: {currentUsage: capacity}}, function(err,updatedUser){
                            if(err || !updatedUser){
                                console.log("error in updating current usage.");
                                return;
                            }else{
            
                            }
                        });

                        if(!flag){
                            req.flash("success", "Item added, however one or more groups exceeded limit.");
                        }else{
                            req.flash("success", "Item successfully added.");
                        }
                        res.redirect("/home");
                    }
                });
                
            }
        });
    });
});

//NEW route - display a form to add new item
app.get("/home/new", isLoggedIn, function(req,res){
    //get all groups from DB
    Group.find({}, function(err,allGroups){
        if(err){
            req.flash("error", "Group not found");
            res.redirect("/home");
        }else{
            res.render("main/newPost", {groups: allGroups});
            //redudant to pass currentUser since we already have a function currUser in app.js to eliminate this need
        }
    });
});

//SHOW route - display one particular park
app.get("/home/:id", isLoggedIn, function(req,res){
    //populating the comments for every park since we used object Ids
    Item.findById(req.params.id).populate("groups").exec(function(err, foundItem){
        if(err || !foundItem){
            req.flash("error", "Item not found");
            res.redirect("/home");
        }else{
            //show info on that id

            res.render("main/show", {item: foundItem});
            foundItem.lastAccess = new Date(Date.now());
            Item.findByIdAndUpdate(req.params.id, foundItem, function(err, updatedWithLastAccessItem){
                if(err){
                    console.log(err);
                }
                else{

                }
            });
        }
    });    
});

//EDIT route - show edit form for one item
app.get("/home/:id/edit", checkItemOwnership, function(req,res){
    Item.findById(req.params.id, function(err, foundItem){
        if(err || !foundItem){
            req.flash("error", "Item not found");
            res.redirect("/home");
        }else{
            //get all groups from DB
            Group.find({}, function(err,allGroups){
                if(err){
                    req.flash("error", "Group not found");
                    res.redirect("/home");
                }else{
                    res.render("main/edit", {item: foundItem, groups: allGroups});
                }
            });            
        }
    });    
});


//UPDATE route - update item
app.put("/home/:id", checkItemOwnership, function(req, res){

    var uploadS3 = multer({
        storage: multers3({
            s3: s3,
            acl: 'public-read',
            bucket: process.env.AWS_BUCKET,
            metadata: (req,file,cb) => {
                cb(null, {fieldname: file.fieldname});
            },
            key: (req,file,cb)=>{
                cb(null, Date.now().toString()+'-'+file.originalname);
            }
        }),
        limits: {
            fileSize: fileLimitUpload * Math.pow(1024, 2)
        }
    }).single('userFile');

    uploadS3(req,res, function(err){
        if(err){
            if(err.code === "LIMIT_FILE_SIZE"){
                req.flash("error", "File Size Too Large. Current Item Size Limit is "+fileLimitUpload+" MB.");
                res.redirect("/home/"+req.params.id+"/edit");
                return;
            }else{
                req.flash("error", "File Upload Error. Try Again");
                res.redirect("/home/"+req.params.id+"/edit");
                return;
            }
        }

        if(!req.file){
            req.flash("error", "Please select a file.");
            res.redirect("/home/"+req.params.id+"/edit");
            return;
        }

        var foundItemToBeDeletedKey;
        var fileSize=0;
        var capacity;
        Item.findById(req.params.id, function(err, foundItem){
            if(err || !foundItem){
                req.flash("error","Item not found");
                res.redirect("/home/");
                return;
            }else{
                foundItemToBeDeletedKey = foundItem.key;
                User.findById(req.user._id, function(err,foundUser){
                    if(err){
                        console.log("error");
                    }else{
                        if(!req.user.isAdmin){
                            fileSize = foundUser.currentUsage - foundItem.size;
                        }                        
                        capacity = fileSize+Number(Math.ceil(req.file.size/(Math.pow(1024,2))));
                        if(capacity > req.user.userLimit){
                            deleteFromS3(req.file.key);
                            req.flash("error","Cannot upload this item as total storage for "+req.user.username+" is exceeding "+req.user.userLimit+" MB.");
                            res.redirect("/home");
                            return;
                        }else{
                            
                        }
                    }
                });
                

            }
        });
        

        Group.find({}, function(err,allGroups){
            if(err){
                deleteFromS3(req.file.key);
                req.flash("error","Group not found");
                res.redirect("/home");
            }else{
                if(req.body.name.length<3 || req.body.name.length>68){
                    deleteFromS3(req.file.key);
                    req.flash("error","Item has should be 3-68 characters.");
                    res.redirect("/home/new");
                    return;
                }
                if(req.body.description.length<6 || req.body.name.length>1000){
                    deleteFromS3(req.file.key);
                    req.flash("error","Item description should be 6-1000 characters");
                    res.redirect("/home/new");
                    return;
                }

                //Code Sanitization
                req.body.name = req.sanitize(req.body.name);
                req.body.description = req.sanitize(req.body.description); 

                req.body.default="on";
                var updatedItem = {
                    name: req.body.name,
                    description: req.body.description,
                    lastAccess: new Date(Date.now()),
                    url: req.file.location,
                    mimeType: req.file.mimetype,
                    fileName: req.file.originalname,
                    key: req.file.key,
                    size: Math.ceil(req.file.size/Math.pow(1024,2)),
                    creator: {
                        id: req.user._id,
                        username: req.user.username
                    },
                    groups: []
                };
                var flag=true;
                allGroups.forEach(function(group){
                    if(group.groupName in req.body){
                        if(group.currentUsage>group.groupLimit){
                            flag=false;
                        }else{
                            group.currentUsage++;
                            group.save();
                            updatedItem.groups.push(group._id);  
                        }
                    }
                    
                });

                if(updatedItem.groups.length==0){
                    req.flash("error", "Group Limits exceeded for all selected groups.")
                    res.redirect("/home");
                    return;
                }

                Item.findByIdAndUpdate(req.params.id, updatedItem, function(err, addedItem){
                    if(err){
                        req.flash("error","Item not updated");
                        res.redirect("/home");
                    }else{
                        deleteFromS3(foundItemToBeDeletedKey);
                        
                        User.findByIdAndUpdate(req.user._id, {$set: {currentUsage: capacity}}, function(err,updatedUser){
                            if(err || !updatedUser){
                                console.log(err);
                                console.log("error in updating current usage.");
                                return;
                            }else{
            
                            }
                        });

                        if(!flag){
                            req.flash("success", "Item added, however one or more groups exceeded limit.");
                        }else{
                            req.flash("success", "Item updated successfully.");
                        }
                        if(req.user.isAdmin){
                            fillAdmin();
                        }   
                        res.redirect("/home/"+req.params.id);
                    }
                });
            }
        })
    })    
});

//DESTROY route - delete an item
app.delete("/home/:id", checkItemOwnership, function(req,res){

    var foundItemToBeDeletedKey;
    var fileSize=0;
    Item.findById(req.params.id, function(err, foundItem){
        if(err || !foundItem){
            req.flash("error","Item not found");
            res.redirect("/home/");
            return;
        }else{
            Group.find({}, function(err,foundGroups){
                if(err){
                    console.log(err);
                    return;
                }else{
                    foundGroups.forEach(function(group){
                        if(foundItem.groups.includes(group._id)){
                            group.currentUsage--;
                            group.save();
                        }                        
                    });
                }
            });
            

            foundItemToBeDeletedKey = foundItem.key;
            User.findById(req.user._id, function(err,foundUser){
                if(err){
                    console.log("error");
                }else{
                    if(!req.user.isAdmin){
                        fileSize = foundUser.currentUsage - foundItem.size;
                    }else{
                        fileSize = foundUser.currentUsage;
                    }
                    Item.findByIdAndRemove(req.params.id, function(err){
                        if(err){
                            req.flash("error", "Item not found");
                            res.redirect("/home");
                        }else{
                            deleteFromS3(foundItemToBeDeletedKey);
                            User.findByIdAndUpdate(req.user._id, {$set: {currentUsage: fileSize}}, function(err, updatedUser){
                                if(err || !updatedUser){
                                    console.log("Could not change user's current usage");
                                    return;
                                }else{
                                    req.flash("error", "Successfully deleted item");
                                    res.redirect("/home");
                                }
                            });            
                        }
                    });
                }
            });  
        }
    });

    
});


// GROUP ROUTES

//INDEX - SHOW ALL GROUPS
app.get("/groups", isLoggedIn, function(req, res){
    Group.find({}, function(err,allGroups){
        if(err){
            req.flash("error", "Groups not found");
            res.redirect("/");
            return;
        }else{
            Item.countDocuments(function(err,count){
                if(err){
                    console.log("error in count");
                }else{
                    var flag = false;
                    if(count>0){
                        flag=true;
                    }
                    res.render("groups/groups", {groups: allGroups, flag: flag, page: "group"});
                }
            });
            
        }
    });
});

//NEW - MAKE NEW GROUP
app.get("/groups/new", isLoggedIn, function(req, res){
    res.render("groups/new");
});

//CREATE - MAKE NEW GROUP
app.post("/groups", isLoggedIn, function(req, res){
    //Code Sanitization
    req.body.name = req.sanitize(req.body.name);
    var isActive = false;
    if(req.user.isAdmin){
        isActive = true;
    }
    var newGroup  = {
        groupName: req.body.name,
        isActive: isActive
    };

    Group.create(newGroup, function(err, addedGroup){
        if(err){
            req.flash("error","Group not created");
            res.redirect("/groups");
        }else{
            if(req.user.isAdmin){
                fillAdmin();
            }
            req.flash("success", "Group successfully added. Please wait for an admin to accept the group.");
            res.redirect("/groups");
        }
    });

});


//SHOW ITEMS IN A SPECIFIC GROUPS
app.get("/groups/:id", isLoggedIn, function(req,res){
    Group.findById(req.params.id, function(err,foundGroup){
        if(err){
            req.flash("error","Group Not Found");
            res.redirect("/groups");
            return;
        }else{
            Item.find({}, function(err, foundItem){
                if(err){
                    req.flash("error", "Items Not Found");
                    res.redirect("/groups");
                    return;
                }else{
                    res.render("groups/show", {items: foundItem, group: foundGroup});
                }
            });
        }
    });
    
});

//ADMIN ROUTES

//INDEX- GET ROUTE
app.get("/admin", isAdmin, function(req,res){
    User.find({}, function(err, foundUsers){
        if(err){
            console.log("Error in Admin user find.");
            res.redirect("/home");
        }else{
            Group.find({}, function(err, foundGroups){
                if(err){
                    console.log("Error in Group Admin user find.");
                    res.redirect("/home");
                }else{
                    res.render("admin/index",{users:foundUsers, groups:foundGroups});
                }
            });
        }
    });
});

//INDEX- POST ROUTE
app.post("/admin", isAdmin, function(req,res){
    if(req.body.itemSize>=1 && req.body.itemSize<=10){
        fileLimitUpload = req.body.itemSize;
    }else{
        req.flash("error"," Incorrect item file size limits.");
        res.redirect("/admin");
        return;
    }
    
    req.flash("success","Item Size Limit successfully changed to "+fileLimitUpload+" MB.");
    res.redirect("/admin");
});

//SHOW - SHOW INDIVIDUAL USERS
app.get("/admin/:id", isAdmin, function(req,res){
    User.findById(req.params.id, function(err, foundUser){
        if(err || !foundUser){
            req.flash("error","No such User Exists!");
            res.redirect("/admin");
            return;
        }else{
            Group.find({},function(err, foundGroups){
                if(err){
                    console.log("No groups");
                    return;
                }else{
                    res.render("admin/show",{user: foundUser, groups:foundGroups});
                }
            });
        }
    });
});

//UPDATE route - update user
app.put("/admin/:id", isAdmin, function(req, res){
    
    var isActiveStatus = false;
    var isAdminStatus = false;
    if(req.body.isActive==='yes'){
        isActiveStatus=true;
    }
    if(req.body.isAdmin ==='yes'){
        isAdminStatus = true;
    }

    if(req.body.itemSize>=5 && req.body.itemSize<=25){
        
    }else{
        req.flash("error"," Incorrect user storage size limits.");
        res.redirect("/admin/"+req.params.id);
        return;
    }

    Group.find({},function(err,allGroups){
        if(err){
            console.log("couldnt find groups.");
            return;
        }else{
            req.body.default = "on";
            tempgroups=[];
            allGroups.forEach(function(group){
                if(group.groupName in req.body){
                    tempgroups.push(group._id);  
                }
            });

            User.findByIdAndUpdate(req.params.id, {$set: {isActive: isActiveStatus, isAdmin: isAdminStatus, groups: tempgroups, userLimit: req.body.itemSize}}, function(err,updatedUser){
                if(err || !updatedUser){
                    req.flash("User Details not updated.");
                    res.redirect("/admin");
                    return;
                }else{
                    if(isAdminStatus){
                        fillAdmin();
                    }            
                    req.flash("success","Updated User Details.");
                    res.redirect("/admin/");
                }
            });
        }
    });
});

//SHOW - SHOW GROUPS
app.get("/admin/groups/:id", isAdmin, function(req,res){
    Group.findById(req.params.id, function(err, foundGroup){
        if(err || !foundGroup){
            req.flash("error","No such Group Exists!");
            res.redirect("/admin");
            return;
        }else{            
            res.render("admin/showgroup",{group:foundGroup});
        }
    });
});

//UPDATE group 
app.put("/admin/groups/:id", isAdmin, function(req, res){
    var isActiveStatus = false;
    if(req.body.isActive==='yes'){
        isActiveStatus=true;
    }
    
    var groupLimitSize = req.body.itemSize;

    Group.findByIdAndUpdate(req.params.id, {$set: {isActive: isActiveStatus, groupLimit: groupLimitSize}}, function(err,updatedGroup){
        if(err || !updatedGroup){
            req.flash("error","Group Details not updated.");
            res.redirect("/admin");
            return;
        }else{
            if(isActive){
                fillAdmin();
            }            
            req.flash("success","Updated Group Details.");
            res.redirect("/admin/");
        }
    });
        
});


// USER - show user stats
app.get("/user/:id", isLoggedIn, isSaidUser, function(req,res){
    User.findById(req.params.id, function(err, foundUser){
        if(err || !foundUser){
            req.flash("error","No such User Exists!");
            res.redirect("/home");
            return;
        }else{
            Group.find({},function(err, foundGroups){
                if(err){
                    console.log("No groups");
                    return;
                }else{
                    res.render("user/show",{user: foundUser, groups:foundGroups});
                }
            });
        }
    });
});


//Middleware
function isLoggedIn(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    //else
    req.flash("error", "You need to be logged in to do that!");
    res.redirect("/login");
}

function isLoggedOut(req, res, next){
    if(!req.isAuthenticated()){
        return next();
    }
    //else
    req.flash("error", "Already logged in.");
    res.redirect("/home");
}

//middleware for items
function checkItemOwnership(req,res,next){
    if(req.isAuthenticated()){
        Item.findById(req.params.id, function(err, foundItem){
            if(err || !foundItem){
                req.flash("error", "Item not found");
                res.redirect("back");
            }else{
                if(foundItem.creator.id.equals(req.user._id) || req.user.isAdmin){
                    next();
                }else{
                    req.flash("error", "You don't have permission to do that");
                    res.redirect("/home/"+req.params.id);
                }
            }
        });
    }else{
        req.flash("error", "You need to be logged in to do that!");
        res.redirect("/login");
    }
}

function isAdmin(req,res,next){
    if(req.isAuthenticated()){
        if(req.user.isAdmin){
            next();
        }else{
            req.flash("error", "You do not have permission to do that!");
            res.redirect("/home");
        }
    }else{
        req.flash("error", "You need to log in first!");
        res.redirect("/login");
    }
}

function fillAdmin(){
    User.find({isAdmin: true}, function(err, foundUsers){
        if(err){
            console.log("Error in admin func");
        }else{
            foundUsers.forEach(function(admin){
                admin.groups = [];
                Group.find({}, function(err, foundGroup){
                    if(err){
                        req.flash("error", "Groups not found");
                        res.redirect("/");
                        return;
                    }else{
                        foundGroup.forEach(function(group){
                            if(group.isActive){
                                admin.groups.push(group._id);
                            }                            
                        });
                        if(!admin.currentUsage){
                            admin.currentUsage=0;
                        }
                        admin.save();
                    }
                });
        
            });
        }
    })
}

function isActive(req, res, next){
    if(req.user.isActive){
        return next();
    }
    //else
    res.render("auth/wait");
}

function isSaidUser(req,res,next){
    
    User.findById(req.params.id, function(err, foundUser){
        if(err || !foundUser){
            req.flash("error", "Item not found");
            res.redirect("back");
        }else{
            if(foundUser._id.equals(req.user._id)){
                next();
            }else{
                req.flash("error", "You don't have permission to do that");
                res.redirect("/home/");
            }
        }
    });
}

var port = process.env.PORT || 3000;

app.listen(port, process.env.IP, function(){
    console.log("SPPP Server is running");
});