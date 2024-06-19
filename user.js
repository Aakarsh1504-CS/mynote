const mongoose=require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema=mongoose.Schema({
    email:{type:String,unique:true},
    name:String,
    password:String,
    notes:[
        {
            type:mongoose.Schema.Types.ObjectId,
            ref:"post"
        }
    ]
});

module.exports=mongoose.model("user",userSchema);