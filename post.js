const mongoose=require('mongoose');

const postSchema=mongoose.Schema({
    title:String,
    content:String,
    owner:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"user"
    }
});

module.exports=mongoose.model("post",postSchema);