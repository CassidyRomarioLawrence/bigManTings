// Database configuration
const db = require('../config');
// bcrypt module
const {hash, compare, hashSync } = require('bcrypt');
// Middleware for creating a token
const { createToken } = require('../middleware/AuthenticatedUser');
//User
class User {
    login(req, res) {
        const {email, userPass} = req.body;
        const strQry = 
        `
        SELECT firstName, lastName, gender, email, userPass, userRole, userImage
        FROM users
        WHERE email = '${email}';
        `;
        db.query(strQry, async (err, data)=>{
            if(err) throw err;
            if((!data.length) || (data == null)) {
                res.status(401).json({err: 
                    "Incorrect email address"});
            }else {
                await compare(userPass, 
                    data[0].userPass, 
                    (cErr, cResult)=> {
                        if(cErr) throw cErr;
                        // Create a token
                        const jwToken = 
                        createToken(
                            {
                                email, userPass  
                            }
                        );
                        // Saving
                        res.cookie('LegitUser',
                        jwToken, {
                            maxAge: 3600000,
                            httpOnly: true
                        })
                        if(cResult) {
                            res.status(200).json({
                                msg: 'Logged In',
                                jwToken,
                                result: data[0]
                            })
                        }else {
                            res.status(401).json({
                                err: 'Incorrect password'
                            })
                        }
                    })
            }
        })     
    }
    fetchUsers(req, res) {
        const strQry = 
        `
        SELECT userId, firstName, lastName, gender, phoneNumber, email, userRole, userImage
        FROM users;
        `;
        //db
        db.query(strQry, (err, data)=>{
            if(err) throw err;
            else res.status(200).json( 
                {results: data} );
        })
    }
    fetchUser(req, res) {
        const strQry = 
        `
        SELECT userId, firstName, lastName, gender, phoneNumber, email, userRole, userImage
        FROM users
        WHERE userId = ?;
        `;
        //db
        db.query(strQry,[req.params.userId], 
            (err, data)=>{
            if(err) throw err;
            else res.status(200).json( 
                {results: data} );
        })

    }
    async createUser(req, res) {
        // Payload
        let info = req.body;
        // Hashing user password
        info.userPass = await 
        hash(info.userPass, 15);
        // This information will be used for authentication.
        let user = {
            email: info.email,
            userPass: info.userPass
        }
        // sql query
        const strQry =
        `INSERT INTO users
        SET ?;`;
        db.query(strQry, [info], (err)=> {
            if(err) {
                res.status(401).json({err});
            }else {
                // Create a token
                const jwToken = createToken(user);
                // This token will be saved in the cookie. 
                // The duration is in milliseconds.
                res.cookie("LegitUser", jwToken, {
                    maxAge: 3600000,
                    httpOnly: true
                });
                res.status(200).json({msg: "Successfully added new user."})
            }
        })    
    }
    updateUser(req, res) {
        let data = req.body;
        if(data.userPass !== null || 
            data.userPass !== undefined)
            data.userPass = hashSync(data.userPass, 15);
        const strQry = 
        `
        UPDATE users
        SET ?
        WHERE userId = ?;
        `;
        //db
        db.query(strQry,[data, req.params.userId], 
            (err)=>{
            if(err) throw err;
            res.status(200).json( {msg: 
                "Successfully updated user."} );
        })    
    }
    deleteUser(req, res) {
        const strQry = 
        `
        DELETE FROM users
        WHERE userId = ?;
        `;
        //db
        db.query(strQry,[req.params.userId], 
            (err)=>{
            if(err) throw err;
            res.status(200).json( {msg: 
                "Successfully deleted user."} );
        })    
    }
}
// Product
class Product {
    fetchProducts(req, res) {
        const strQry = `SELECT id, category, prodName, prodInfo, prodPrice, prodImage
        FROM products;`;
        db.query(strQry, (err, results)=> {
            if(err) throw err;
            res.status(200).json({results: results})
        });
    }
    fetchProduct(req, res) {
        const strQry = `SELECT id,category, prodName, prodInfo, prodPrice, prodImage
        FROM products
        WHERE userId = ?;`;
        db.query(strQry, [req.params.userId], (err, results)=> {
            if(err) throw err;
            res.status(200).json({results: results})
        });

    }
    addProduct(req, res) {
        const strQry = 
        `
        INSERT INTO products
        SET ?;
        `;
        db.query(strQry,[req.body],
            (err)=> {
                if(err){
                    res.status(400).json({err: "Unable to create new product."});
                }else {
                    res.status(200).json({msg: "Product successfully added."});
                }
            }
        );    

    }
    updateProduct(req, res) {
        const strQry = 
        `
        UPDATE products
        SET ?
        WHERE userId = ?
        `;
        db.query(strQry,[req.body, req.params.userId],
            (err)=> {
                if(err){
                    res.status(400).json({err: "Could not update product."});
                }else {
                    res.status(200).json({msg: "Product successfully updated"});
                }
            }
        );    

    }
    deleteProduct(req, res) {
        const strQry = 
        `
        DELETE FROM products
        WHERE userId = ?;
        `;
        db.query(strQry,[req.params.id], (err)=> {
            if(err) res.status(400).json({err: "Product not found."});
            res.status(200).json({msg: "Successfully deleted product."});
        })
    }

}
// Export User class
module.exports = {
    User, 
    Product
}