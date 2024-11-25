const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken"); // Для создания токенов
const helmet = require("helmet");
const { Sequelize, DataTypes } = require("sequelize");
const app = express();
const router = express.Router();
const SECRET_KEY = "your_secret_key"; // Секретный ключ для JWT

// Использование Helmet для защиты сайта
app.use(helmet());
app.use(express.json());
app.use(bodyParser.json());

// Настраиваем CORS для разрешения запросов только с http://localhost:3000
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["POST", "GET"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Подключение к базе данных
const sequelize = new Sequelize("MT", "root", "", {
  host: "localhost",
  dialect: "mysql",
});

const User = sequelize.define("User", {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  token_admin: {
    type: DataTypes.INTEGER,
    defaultValue: 1,
  },
}, {
  timestamps: false, // Отключает createdAt и updatedAt
});

const Question = sequelize.define("Question", {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  phone: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isEmail: true, // Проверка, что это корректный email
    },
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
}, {
  timestamps: false, // Отключаем создание полей createdAt и updatedAt
});
// Подключение к базе данных
sequelize
  .authenticate()
  .then(() => {
    console.log("Успешное подключение к базе данных.");
  })
  .catch((err) => {
    console.error("Ошибка подключения к базе данных:", err);
  });

// Синхронизация модели с базой данных
sequelize.sync();

// Маршрут для регистрации пользователей
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Пожалуйста, заполните все поля" });
  }

  try {
    const emailExists = await User.findOne({ where: { email } });
    if (emailExists) {
      return res.status(400).json({ message: "Этот email уже зарегистрирован" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email, password: hashedPassword });

    console.log("Добавлен новый пользователь:", newUser);
    res.status(200).json({ message: "Регистрация прошла успешно" });
  } catch (err) {
    console.error("Ошибка при регистрации пользователя:", err);
    res.status(500).json({ message: "Ошибка сервера", error: err });
  }
});

// Маршрут для авторизации пользователей и администратора
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Пожалуйста, заполните все поля" });
  }

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(400).json({ message: "Неверный email или пароль" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Неверный email или пароль" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        token_admin: user.token_admin,
      },
      SECRET_KEY,
      { expiresIn: "1y" }
    );

    res.status(200).json({
      message: "Авторизация успешна",
      token,
      token_admin: user.token_admin,
    });

    console.log(`Токен:`, token);
    console.log(`почта`, email);
    console.log(`Роль пользователя: ${user.token_admin == 2 ? 'Администратор' : 'Пользователь'}`);

  } catch (err) {
    console.error("Ошибка при авторизации:", err);
    res.status(500).json({ message: "Ошибка сервера", error: err });
  }
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
// проверка почты для сброса пароля
router.post("/check-email", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email не предоставлен." });
  }

  try {
    // Используем метод findOne для поиска пользователя по email
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ message: "Email не найден.", exists: false });
    }

    return res.status(200).json({ message: "Email найден.", exists: true });
  } catch (error) {
    console.error("Ошибка при проверке email:", error);
    return res.status(500).json({ message: "Ошибка сервера.", error });
  }
});

//изменение пароля
router.post("/change-password", async (req, res) => {
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
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Пользователь с указанным email не найден." });
    }

    // Хэшируем новый пароль
    const hashedPassword = await bcrypt.hash(password, 10);

    // Обновляем пароль в базе данных
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: "Пароль успешно изменен." });
  } catch (err) {
    console.error("Ошибка на сервере:", err);
    res
      .status(500)
      .json({ message: "Произошла ошибка на сервере.", error: err });
  }
});

//форма отправки вопросов клиентов

// Маршрут для отправки вопросов клиентов
router.post("/questions", async (req, res) => {
  const { name, phone, email, description } = req.body;

  if (!name || !phone || !email || !description) {
    return res.status(400).json({ message: "Заполните обязательные поля" });
  }

  // Регулярное выражение для проверки правильности email
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailPattern.test(email)) {
    return res.status(400).json({ message: "Пожалуйста, введите корректный email" });
  }

  try {
    // Создаем новую запись в таблице вопросов
    const newQuestion = await Question.create({
      name,
      phone,
      email,
      description,
    });

    // Если запрос выполнен успешно, отправляем ответ с успешным результатом
    res.status(201).json({ message: "Данные успешно сохранены", id: newQuestion.id });
  } catch (err) {
    console.error("Ошибка при сохранении данных:", err);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

//вывод пользователей
router.get("/users", async (req, res) => {
  try {
    // Извлекаем всех пользователей, выбираем нужные поля
    const users = await User.findAll({
      attributes: ['id', 'email', 'token_admin'], // Поля, которые нужно вернуть
    });

    // Отправляем список пользователей
    res.status(200).json({ users });
  } catch (err) {
    console.error("Ошибка при получении данных пользователей:", err);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});
// вывод вопросов пользователей
router.get("/question", async (req, res) => {
  try {
    // Извлекаем все вопросы с необходимыми полями
    const questions = await Question.findAll({
      attributes: ['id', 'name', 'email', 'phone', 'description'], // Поля, которые нужно вернуть
    });

    // Отправляем список вопросов
    res.status(200).json({ questions });
  } catch (err) {
    console.error("Ошибка при получении данных из questions:", err);
    res.status(500).json({
      message: "Ошибка при получении данных",
      error: err,
    });
  }
});

app.use("/api", router);
// Запуск сервера
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Сервер работает на порту ${PORT}`);
});
