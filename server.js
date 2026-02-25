
const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
require("dotenv").config();
const session = require("express-session");
const  MongoStore    = require("connect-mongo");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");
const { ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;



const app = express();
app.use(cookieParser());

app.use(cors({
  origin: true,
  credentials: true
}));

















app.use(passport.initialize());

app.use(compression({ level: 6 }));

app.use(express.static(__dirname));

app.use("/images", express.static(__dirname + "/images"));

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));


app.use(session({
  name: "SakhiMart.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,

  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: "sessions",
    ttl: 6 * 60 * 60 // ✅ 1 DAY

  }),

  cookie: {
    secure: false,        // Required on HTTPS (Render)
    httpOnly: true,
    sameSite: "lax",
    maxAge: 1000 * 6 * 60 * 60 // ✅ 1 DAY
  },proxy: true
}));



// Mongo
const { MongoClient } = require("mongodb");
const client = new MongoClient(process.env.MONGO_URI);

let db;
let Products; 
let Categories; 
let Users;
let Orders;

async function connectDB() {
  try {
    await client.connect();
    console.log("✅ MongoDB Connected");

    db = client.db("SakhiMart"); // Your DB Name
    Products = db.collection("products");  
    Categories = db.collection("categories"); 
    Users = db.collection("users");
    Orders = db.collection("orders");
  } catch (error) {
    console.error("❌ MongoDB Connection Failed:", error);
    process.exit(1);
  }
}

connectDB();







// ================= IMAGE UPLOAD =================

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "products_images/");
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage: storage });

app.use("/products_images", express.static("products_images"));
















passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://unishop-gxq5.onrender.com/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {

  let user = await Users.findOne({ email: profile.emails[0].value });

  if (!user) {
    const newUser = {
      name: profile.displayName,
      username: profile.emails[0].value.split("@")[0],
      email: profile.emails[0].value,
      provider: "google",
      createdAt: new Date()
    };

    const result = await Users.insertOne(newUser);
    user = { _id: result.insertedId, ...newUser };
  }

  return done(null, user);
}));


app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {

    const token = jwt.sign(
      { id: req.user._id, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    // In /auth/google/callback
res.redirect(`/?token=${token}`);
  }
);




app.post("/api/signup", async (req, res) => {
  try {
    const { name, username, email, password } = req.body;

    if (!name || !username || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existingUser = await Users.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      name,
      username,
      email,
      password: hashedPassword,
      provider: "local",
      createdAt: new Date()
    };

    const result = await Users.insertOne(newUser);

    const token = jwt.sign(
      { id: result.insertedId, email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });

  } catch (error) {
    res.status(500).json({ message: "Signup failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await Users.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });

  } catch (error) {
    res.status(500).json({ message: "Login failed" });
  }
});

























app.get("/api/products", async (req, res)=>{

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    const skip = (page - 1) * limit;

    const products = await Products
        .find()
        .skip(skip)
        .limit(limit)
        .toArray();

    res.json(products);
});









app.get("/api/admin/products", async (req, res)=>{

    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    const total = await Products.countDocuments();
    const products = await Products
        .find()
        .skip(skip)
        .limit(limit)
        .toArray();

    res.json({
        products,
        totalPages: Math.ceil(total / limit)
    });
});



app.get("/api/product/:id", async (req, res)=>{
    const product = await Products.findOne({
        _id: new ObjectId(req.params.id)
    });

    res.json(product);
});

app.delete("/api/delete-product/:id", async (req, res)=>{
    await Products.deleteOne({
        _id: new ObjectId(req.params.id)
    });

    res.json({message:"Deleted"});
});


app.put("/api/update-product/:id", upload.single("image"), async (req, res)=>{

    let updateData = req.body;

    if(req.file){
        updateData.image = "/products_images/" + req.file.filename;
    }

    if(updateData.price){
        updateData.price = parseFloat(updateData.price);
    }

    await Products.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateData }
    );

    res.json({message:"Updated"});
});



app.post("/api/add-product", upload.single("image"), async (req, res) => {
  try {
    const {
      title,
      description,
      section,
      category,
      price,
      imageLink
    } = req.body;

    let imagePath = "";

    if (req.file) {
      imagePath = "/products_images/" + req.file.filename;
    } else if (imageLink) {
      imagePath = imageLink;
    }

    const newProduct = {
      title,
      description,
      section,
      category,
      price: parseFloat(price),
      image: imagePath,
      reviews: []
    };

    await Products.insertOne(newProduct);

    res.json({ success: true, message: "Product Added Successfully" });

  } catch (error) {
    res.status(500).json({ success: false, message: "Error Adding Product" });
  }
});





app.get("/api/categories", async (req, res)=>{
    const categories = await Categories.find().toArray();
    res.json(categories);
});



app.post("/api/add-category", async (req, res) => {

    const { section, categoryName, image } = req.body;

    await Categories.updateOne(
        { name: section },
        { 
            $addToSet: { 
                items: { name: categoryName, image: image } 
            } 
        },
        { upsert: true }
    );

    res.json({ message: "Category Added" });
});




app.delete("/api/delete-category", async (req, res)=>{

    const { section, categoryName } = req.body;

    await Categories.updateOne(
        { name: section },
        { $pull: { items: { name: categoryName } } }
    );

    res.json({ message: "Category Deleted" });
});


app.get("/api/categories/:section", async (req, res) => {

    const section = req.params.section;

    const category = await Categories.findOne({ name: section });

    if (!category) return res.json([]);

    res.json(category.items || []);
});












app.post("/api/search-products", async (req, res) => {

    const { search } = req.body;

    // Store in session
    req.session.searchQuery = search;

    res.json({ redirect: "/products.html" });
});

app.get("/api/get-search-products", async (req, res) => {

    const query = req.session.searchQuery || "";

    const products = await Products.find({
        title: { $regex: query, $options: "i" }
    }).toArray();

    res.json({
        search: query,
        products
    });
});











app.get("/api/products-by-category", async (req, res) => {

    const { section, category } = req.query;

    if(!section || !category){
        return res.json([]);
    }

 const products = await Products.find({
    section: { $regex: section, $options: "i" },
    category: { $regex: category, $options: "i" }
}).toArray();

    res.json(products);
});












// Total users
app.get("/api/admin/users-count", async (req,res)=>{
    const total = await Users.countDocuments();
    res.json({ total });
});

// Total products
app.get("/api/admin/products-count", async (req,res)=>{
    const total = await Products.countDocuments();
    res.json({ total });
});

// Total categories
app.get("/api/admin/categories-count", async (req,res)=>{
    const total = await Categories.countDocuments();
    res.json({ total });
});

// Products per section (for chart)
app.get("/api/admin/products-per-section", async (req,res)=>{
    const sections = ["Men","Women","Kids","Baby"];
    const counts = {};
    for(let sec of sections){
        counts[sec] = await Products.countDocuments({ section: sec });
    }
    res.json(counts); // MUST be an object, not array
});
















// Get all users
app.get("/api/admin/users", async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const users = await Users.find().skip(skip).limit(limit).toArray();
    const totalUsers = await Users.countDocuments();

    res.json({ users, totalUsers });
});

// Delete a user
app.delete("/api/admin/delete-user/:id", async (req, res) => {
    const id = req.params.id;
    try {
        await Users.deleteOne({ _id: new ObjectId(id) });
        res.json({ message: "User deleted" });
    } catch(err) {
        res.status(500).json({ message: "Failed to delete user" });
    }
});









app.post("/api/order", async (req, res) => {
    try {
        const { product, customer, userEmail, delivery, createdAt } = req.body;

        if(!userEmail || !product || !customer) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const order = {
            product,
            userEmail,
            customer,
            delivery: delivery || [
                { stage: "Reached", status: false },
                { stage: "Shipped", status: false },
                { stage: "Delivered", status: false }
            ],
            createdAt: createdAt || new Date()
        };

        const result = await Orders.insertOne(order);

        res.json({ success: true, orderId: result.insertedId });
    } catch(err) {
        console.error(err);
        res.status(500).json({ message: "Order failed" });
    }
});



// Corrected GET route using the same collection as POST
app.get("/api/orders", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email required" });

  try {
    // Use the same collection/variable as in POST (Orders)
    const orders = await Orders.find({ userEmail: email }).sort({ createdAt: -1 }).toArray();
    res.json(orders);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});



app.delete("/api/order/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const result = await Orders.deleteOne({ _id: new ObjectId(id) });
    if(result.deletedCount === 1){
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  } catch(err){
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to delete order" });
  }
});






// Admin: Get all orders with pagination
app.get("/admin/api/orders", async (req, res) => {
    let { page = 1, limit = 10 } = req.query;
    page = parseInt(page);
    limit = parseInt(limit);

    try {
        const totalOrders = await Orders.countDocuments();
        const orders = await Orders.find()
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .toArray();

        res.json({ orders, totalOrders });
    } catch(err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch orders" });
    }
});

// Admin: Delete order
app.delete("/admin/api/order/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const result = await Orders.deleteOne({ _id: new ObjectId(id) });
        if(result.deletedCount === 1){
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    } catch(err){
        console.error(err);
        res.status(500).json({ success: false, message: "Failed to delete order" });
    }
});

// Admin: Update delivery status
app.put("/admin/api/order/:id/update-delivery", async (req, res) => {
    const { id } = req.params;
    const { index, status } = req.body;

    try {
        const order = await Orders.findOne({ _id: new ObjectId(id) });
        if(!order) return res.status(404).json({ error: "Order not found" });

        order.delivery[index].status = status;
        await Orders.updateOne({ _id: new ObjectId(id) }, { $set: { delivery: order.delivery } });

        res.json({ success: true });
    } catch(err){
        console.error(err);
        res.status(500).json({ error: "Failed to update delivery" });
    }
});




// Admin: Get single order by ID
app.get("/admin/api/order/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const order = await Orders.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).json({ error: "Order not found" });

        res.json(order);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch order" });
    }
});




// Admin Login API using .env credentials
app.post("/admin/login", async (req,res) => {
    const { id, password } = req.body;

    try {
        // Check against .env credentials
        if(id !== process.env.ADMIN_ID || password !== process.env.ADMIN_PASS){
            return res.status(401).json({ success: false, message: "Invalid Admin ID or Password" });
        }

        // ✅ Save session
        req.session.admin = {
            adminId: id
        };

        res.json({ success: true, message: "Login successful" });

    } catch(err){
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});




app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// Protect /admin/dashboard
app.get("/admin/dashboard", (req,res)=>{
    if(!req.session.admin){
        return res.redirect("/admin-login"); // not logged in
    }

    res.sendFile(__dirname + "/admin-dashboard.html"); // your admin page
});


// Logout
app.get("/admin/logout", (req,res)=>{
    req.session.destroy(err=>{
        if(err) console.error(err);
        res.redirect("/admin-login");
    });
});

app.get("/admin-login", (req, res) => {
  res.sendFile(__dirname + "/admin_login.html");
});


app.get("/products", (req, res) => {
  res.sendFile(__dirname + "/products.html");
});

app.get("/cart", (req, res) => {
  res.sendFile(__dirname + "/Cart.html");
});


app.get("/orders", (req, res) => {
  res.sendFile(__dirname + "/Order.html");
});

app.get("/category", (req, res) => {
  res.sendFile(__dirname + "/Category.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});


app.get("/product-item", (req, res) => {
  res.sendFile(__dirname + "/products_item.html");
});





















const PORT = 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
