import express from 'express';
import cookieParser from 'cookie-parser';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.send("Server is running");
});

app.listen(5000, () => {
    console.log("Server is running on port 5000");
});