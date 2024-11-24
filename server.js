const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken"); // Для создания токенов
const helmet = require("helmet");

const app = express();
const router = express.Router();
const SECRET_KEY = "your_secret_key"; // Секретный ключ для JWT

// Использование Helmet для защиты сайта
app.use(helmet());

// Настраиваем CORS для разрешения запросов только с http://localhost:3000
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["POST", "GET"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
app.use(bodyParser.json());

// Подключение к базе данных
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "MT",
});

db.connect((err) => {
  if (err) {
    console.error("Ошибка подключения к базе данных:", err);
  } else {
    console.log("Подключено к базе данных MySQL");
  }
});

// Маршрут для регистрации пользователей
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Пожалуйста, заполните все поля" });
  }

  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailPattern.test(email)) {
    return res
      .status(400)
      .json({ message: "Пожалуйста, введите корректный email" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Ошибка при проверке email", error: err });
      }

      if (results.length > 0) {
        return res
          .status(400)
          .json({ message: "Этот email уже зарегистрирован" });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query =
          "INSERT INTO users (email, password, token_admin) VALUES (?, ?, 1)";
        db.query(query, [email, hashedPassword], (err, result) => {
          if (err) {
            console.error("Ошибка при добавлении в базу:", err);
            return res.status(500).json({
              message: "Ошибка при добавлении данных в базу",
              error: err,
            });
          }
          console.log("Результат запроса:", result); // Логируем результат запроса в базу
          console.log("Добавлен новый пользователь с email:", email); // Логируем email добавленного пользователя
          console.log("Токен администратора:", 1);

          res.status(200).json({ message: "Регистрация прошла успешно" });
        });
      } catch (err) {
        return res
          .status(500)
          .json({ message: "Ошибка при хэшировании пароля", error: err });
      }
    }
  );
});

// Маршрут для авторизации пользователей и администратора
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Пожалуйста, заполните все поля" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Ошибка при проверке пользователя", error: err });
      }

      if (results.length === 0) {
        return res.status(400).json({ message: "Неверный email или пароль" });
      }

      const user = results[0];

      // Проверяем пароль
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ message: "Неверный email или пароль" });
      }

      // Генерируем JWT токен
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          token_admin: user.token_admin, // Роль пользователя
        },
        SECRET_KEY,
        { expiresIn: "1y" } // Время жизни токена
      );

      res.status(200).json({
        message: "Авторизация успешна",
        token,
        token_admin: user.token_admin,
        role: user.token_admin === 2 ? "admin" : "user",
      });

      console.log(`Токен:`, token);
      console.log(`почта`, email);
      console.log(
        `Роль пользователя: ${
          user.token_admin == 2 ? "Администратор" : "Пользователь"
        }`
      );
    }
  );
});

// Маршрут для проверки администратора
router.post("/admin", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Токен не предоставлен" });
  }

  const token = authHeader.split(" ")[1];
  console.log(`Токен:`, token); // Выводим токен в консоль для проверки

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log("Декодированный токен:", decoded); // Выводим декодированное содержимое токена

    if (decoded.token_admin !== 2) {
      console.log("Ошибка доступа: Недостаточно прав"); // Выводим ошибку, если это не админ
      return res.status(403).json({ message: "Доступ запрещен" });
    }

    // Если роль администратора проверена успешно
    console.log(`Привет, админ!`); // Приветствие в консоль
    res.status(200).json({ message: "Добро пожаловать, администратор!" });
  } catch (err) {
    console.error("Ошибка при верификации токена:", err); // Выводим ошибку при верификации
    res.status(401).json({ message: `Неверный токен`, error: err });
  }
  console.log(
    `Роль пользователя: ${
      user.token_admin === 2 ? "Администратор" : "Пользователь"
    }`
  );
});

router.post("/check-email", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email не предоставлен." });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Ошибка сервера.", error: err });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ message: "Email не найден.", exists: false });
    }

    return res.status(200).json({ message: "Email найден.", exists: true });
  });
});

//изменение пароля
router.post("/change-password", (req, res) => {
  const { email, password } = req.body;

  try {
    // Проверка: заполнены ли поля и длина пароля
    if (!email || !password) {
      return res.status(400).json({
        message: "Пожалуйста, заполните все поля.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Пароль должен содержать минимум 6 символов.",
      });
    }

    // Проверяем, существует ли пользователь с указанным email
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Ошибка при проверке пользователя", error: err });
      }

      if (results.length === 0) {
        return res
          .status(400)
          .json({ message: "Пользователь с указанным email не найден." });
      }

      // Хэшируем новый пароль
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Ошибка при хэшировании пароля", error: err });
        }

        // Обновляем пароль в базе данных
        db.query(
          "UPDATE users SET password = ? WHERE email = ?",
          [hashedPassword, email],
          (err, result) => {
            if (err) {
              return res
                .status(500)
                .json({ message: "Ошибка при обновлении пароля", error: err });
            }

            res.status(200).json({ message: "Пароль успешно изменен." });
          }
        );
      });
    });
  } catch (err) {
    console.error("Ошибка на сервере:", err);
    res
      .status(500)
      .json({ message: "Произошла ошибка на сервере.", error: err });
  }
});

//форма отправки вопросов клиентов

// Маршрут для отправки вопросов клиентов
router.post("/questions", (req, res) => {
  const { name, phone, email, description } = req.body;

  if (!name || !phone || !email || !description) {
    return res.status(400).json({ message: "Заполните обязательные поля" });
  }

  // Регулярное выражение для проверки правильности email
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailPattern.test(email)) {
    return res.status(400).json({ message: "Пожалуйста, введите корректный email" });
  }

  // Запрос на вставку данных в таблицу вопросов
  const query = "INSERT INTO questions (name, phone, email, description) VALUES (?, ?, ?, ?)";
  db.query(query, [name, phone, email, description], (err, results) => {
    if (err) {
      console.error("Ошибка при сохранении данных:", err);
      return res.status(500).json({ message: "Ошибка сервера" });
    }

    // Если запрос выполнен успешно, отправляем ответ с успешным результатом
    res.status(201).json({ message: "Данные успешно сохранены", id: results.insertId });
  });
});

//вывод пользователей
router.get("/users", (req, res) => {
  // Запрос к базе данных для получения всех пользователей
  db.query(
    "SELECT id, email, token_admin, created_at FROM users",
    (err, results) => {
      if (err) {
        console.error("Ошибка при получении данных пользователей:", err);
        return res.status(500).json({ message: "Ошибка сервера" });
      }

      // Отправляем список пользователей на клиентскую часть
      res.status(200).json({ users: results });
    }
  );
});

// вывод вопросов пользователей
router.get("/question", (req, res) => {
  db.query(
    "SELECT id, name, email, phone, description, created_at FROM questions",
    (err, results) => {
      if (err) {
        console.error("Ошибка при получении данных из questions:", err);
        return res.status(500).json({
          message: "Ошибка при получении данных",
          error: err,
        });
      }
      res.status(200).json({ questions: results });
    }
  );
});

app.use("/api", router);
// Запуск сервера
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Сервер работает на порту ${PORT}`);
});
