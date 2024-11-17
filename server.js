const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors'); // Импортируем cors

// Создаем приложение Express
const app = express();

// Настраиваем CORS для разрешения запросов только с http://localhost:3000
app.use(cors({
  origin: 'http://localhost:3000', // Адрес клиента
  methods: ['POST', 'GET'],        // Разрешенные методы
  allowedHeaders: ['Content-Type'], // Разрешенные заголовки
}));

app.use(express.json()); // для парсинга JSON в запросах
app.use(bodyParser.json()); // Middleware для парсинга JSON

// Создаем подключение к базе данных MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',         // Имя пользователя MySQL
    password: '',         // Пароль пользователя MySQL
    database: 'MT'        // Имя вашей базы данных
});

// Подключаемся к базе данных
db.connect((err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err);
    } else {
        console.log('Подключено к базе данных MySQL');
    }
});

// Маршрут для регистрации пользователей
app.post('/api/register', async (req, res) => {  // Исправленный локальный маршрут
    const { email, password } = req.body;

    // Проверка на пустые поля
    if (!email || !password) {
        
        return res.status(400).json({ message: 'Пожалуйста, заполните все поля' });
    }

    // Проверка на корректность email
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailPattern.test(email)) {
        return res.status(400).json({ message: 'Пожалуйста, введите корректный email' });
    }

    db.query('SELECT 1', (err, result) => {
        if (err) {
            console.error('Ошибка с базой данных:', err);
        } else {
            console.log('Соединение с базой данных успешно:', result);
        }
    });

    // Проверка на существующий email в базе данных
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Ошибка при проверке email', error: err });
        }

        if (results.length > 0) {
            return res.status(400).json({ message: 'Этот email уже зарегистрирован' });
        }

        // Хэшируем пароль перед сохранением
        try {
            const hashedPassword = await bcrypt.hash(password, 10); // Соль из 10 раундов

            // Запрос на добавление данных в базу
            const query = 'INSERT INTO users (email, password) VALUES (?, ?)';
            db.query(query, [email, hashedPassword], (err, result) => {
                if (err) {
                    console.error('Ошибка при добавлении в базу:', err);
                    return res.status(500).json({ message: 'Ошибка при добавлении данных в базу', error: err });
                }
                console.log('Результат запроса:', result);
            
                res.status(200).json({ message: 'Регистрация прошла успешно' });
            });
        } catch (err) {
            return res.status(500).json({ message: 'Ошибка при хэшировании пароля', error: err });
        }
    });
});

// Запускаем сервер
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Сервер работает на порту ${PORT}`);
});
