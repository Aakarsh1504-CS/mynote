const express=require('express');
const app=express();
const path=require('path');
const bcrypt=require('bcrypt');
const dotenv = require('dotenv');
const jwt=require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const user=require('./user');
const post=require('./post');
const { log } = require('console');
const port= process.env.port || 3000;
dotenv.config();

app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
});
app.set("view engine","ejs");
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,"public")));
app.use(cookieParser());

app.get("/",(req,res)=>{
    res.cookie("token","");
    res.render("index");
});

app.post("/register",(req,res,next)=>{
    let {email,name,pass}=req.body;
    bcrypt.genSalt(10,(err,salt)=>{
        if(err) return next(new Error("Error creating salt"));
        bcrypt.hash(pass,salt,async (err,hash)=>{
            if(err) return next(new Error("Error creating hash"));
            let cuser=await user.create({
                email,
                name,
                password:hash
            });
            let token = jwt.sign({ email, user_id: cuser._id }, process.env.JWT_SECRET);
            res.cookie("token", token, { httpOnly: true, secure: true, sameSite: 'strict' });
            res.redirect("/login");
        });
    });
});

app.get("/login",(req,res)=>{
    res.cookie("token","");
    res.render("login");
});

app.post("/login",async (req,res)=>{
    let {email,pass}=req.body;
    let us=await user.findOne({email});
    if(us){
        bcrypt.compare(pass,us.password,async (err,result)=>{
            if(err) return next(new Error("comparing pass Error"));
            if(result){
                let cuser=await user.findOne({email});
                let token = jwt.sign({ email, user_id: cuser._id }, process.env.JWT_SECRET);
                res.cookie("token", token, { httpOnly: true, secure: true, sameSite: 'strict' });
                res.redirect("/profile");
            } 
            else res.redirect("/");
        });
    }else{
        res.redirect("/");
    }
});

app.get("/profile",isLoggedIn,async (req,res)=>{
    let uid=req.user.user_id;
    let foundUser=await user.findOne({_id:uid}).populate("notes");
    res.render("notes",{owner:foundUser});
});

app.post("/createnote",isLoggedIn,async (req,res)=>{
    let {title,content}=req.body;
    title=title.trim();
    content=content.trim();
    let uid=req.user.user_id;
    let author=await user.findOne({_id:uid});
    let cpost=await post.create({
        title,
        content,
        owner:author._id
    });
    author.notes.push(cpost._id);
    await author.save();
    res.redirect("/profile");
});

app.get("/show/:postname",isLoggedIn,async (req,res,next)=>{
    let uid=req.user.user_id;
    let author=await user.findOne({_id:uid});
    let rpost=await post.findOne({title:req.params.postname,owner:author._id});
    if(rpost) res.render("show",{rpost});
    else return next(new Error("No such post by you"));
});

app.get("/rename/:postname",isLoggedIn,async (req,res,next)=>{
    let uid=req.user.user_id;
    let author=await user.findOne({_id:uid});
    let rpost=await post.findOne({title:req.params.postname,owner:author._id});
    if(rpost) res.render("rename",{rpost});
    else return next(new Error("No such post by you"));
});

app.post("/rename/:oldname",isLoggedIn,async (req,res,next)=>{
    let uid=req.user.user_id;
    let newname=req.body.newname;
    newname=newname.trim();
    let author=await user.findOne({_id:uid});
    let rpost=await post.findOne({title:req.params.oldname,owner:author._id});
    if(rpost){
        let npost=await post.findOneAndUpdate({_id:rpost._id},{title:newname},{new:true});
        res.redirect(`/show/${npost.title}`);
    }else{
        return next(new Error("No such post by you"));
    }
});

app.get("/delete/:postname",isLoggedIn,async (req,res,next)=>{
    let uid=req.user.user_id;
    let author=await user.findOne({_id:uid});
    let rpost=await post.findOne({title:req.params.postname,owner:author._id});
    if(rpost){
         let dpost=await post.findOneAndDelete({_id:rpost._id});
         author.notes.splice(author.notes.indexOf(dpost._id),1);
         await author.save();
         res.redirect("/profile");
    }else{
        return next(new Error("no such post by you"));
    }
});

function isLoggedIn(req,res,next){
    if(!req.cookies.token) res.redirect("/");
    else{
        let data = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
        if(data){
        req.user=data;
        next();
        }
    }
}
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(port);