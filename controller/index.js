const express = require('express');
// path
const path = require('path');
// body-parser
const bodyParser = require('body-parser');
// Router
const router = express.Router();
// Models
const {User, Product} = require('../model');
// Create a user instance
const user = new User();
// Product instance
const product = new Product();

router.get('/', (req, res)=>{
    res.status(200).sendFile(path.join(__dirname, '../view/index.html'));
})
// =========USER's Router========
// Login
router.post('/login', bodyParser.json(), (req, res)=>{
    user.login(req, res);
})
// Retrieve all users
router.get('/users', (req, res)=>{
    user.fetchUsers(req, res);
});
// Update
router.put('/user/:id',bodyParser.json(), (req, res)=>{
    user.updateUser(req, res);
});
// Register
router.post('/register', bodyParser.json(), (req, res)=> {
    user.createUser(req, res);
})
// Delete
router.delete('/user/:id', (req, res)=>{
    user.deleteUser(req, res);
});
// =====Products======
// Fetch all products
router.get('/products', (req, res)=> {
    product.fetchProducts(req, res);
})
// Fetch a single product
router.get('/product/:id', 
(req, res)=> {
    product.fetchProduct(req, res);
})
// Add a new product
router.post('/product', 
bodyParser.json(), 
(req, res)=> {
    product.addProduct(req, res);
})
// Update a product
router.put('/product/:id', 
bodyParser.json(),
(req, res)=> {
    product.updateProduct(req, res);
})
// Delete a product
router.delete('/product/:id', 
(req, res)=> {
    product.deleteProduct(req, res);
})

module.exports = router;