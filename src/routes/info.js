const express = require("express");
const { verifyAdmin } = require("../middlewares/auth");
const Info = require("../models/Info");
const router = express.Router();
const { clearInfoCache } = require("../services/cache");

router.post("/add-info", verifyAdmin, async (req,res)=>{
  const { title,message,type }=req.body;
  if(!title||!message) return res.status(400).json({ message:"Campi mancanti" });
  const info = await Info.create({ title,message,type:type||"info",createdBy:req.user.schoolEmail });
  clearInfoCache();
  res.status(201).json({ message:"Avviso aggiunto", info });
});

router.post("/delete-info", verifyAdmin, async (req,res)=>{
  const { id }=req.body;
  if(!id) return res.status(400).json({ message:"ID mancante" });
  const deleted=await Info.findByIdAndDelete(id);
  if(!deleted) return res.status(404).json({ message:"Post non trovato" });
  clearInfoCache();
  res.json({ message:"Post eliminato", deleted });
});

router.post("/update-info", verifyAdmin, async (req,res)=>{
  const { id, title, message, type } = req.body;
  if(!id||!title||!message||!type) return res.status(400).json({ message:"Campi mancanti" });
  const updated = await Info.findByIdAndUpdate(id,{ title,message,type },{ new:true });
  if(!updated) return res.status(404).json({ message:"Post non trovato" });
  clearInfoCache();
  res.json({ message:"Avviso aggiornato", info:updated });
});

router.get("/get-info", async (req,res)=>{
  let page=parseInt(req.query.page)||1;
  const limit=15;
  const skip=(page-1)*limit;
  const infos = await Info.find({}, { createdBy:0 }).sort({ createdAt:-1 }).skip(skip).limit(limit);
  const total = await Info.countDocuments();
  res.json({ infos,total,page,totalPages:Math.ceil(total/limit) });
});

module.exports = router;