const express = require('express');
const path = require('path'); // built-in module
const app = express();

// If your HTML file is in the same folder as this script
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Or, if you put HTML in a 'public' folder, you can serve it statically:
// app.use(express.static('public'));

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
