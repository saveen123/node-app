const express = require('express');
const app = express();

app.get('/', (req,res)=>{
	res.send('Api working betterr')
})

app.listen(3000, ()=>{
	console.log('Server is running')
})
