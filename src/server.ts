import express, { Request, Response, RequestHandler, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { words } from './words';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// Расширяем тип Request для добавления user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        email: string;
      };
    }
  }
}

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

interface LevelState {
  easy: boolean;
  middle: boolean;
  hight: boolean;
}
interface WordState {
  id: number;
  word: string;
  translate: string;
  know: boolean;
}

interface UserState {
  email: string;
  token: string;
  id: number;
  name: string;
  image: string;
  studiedWords: WordState[];
  level: LevelState;
  stressTime: number;
  translate: boolean;
  password?: string;
}

const initialState: UserState = {
  email: "",
  token: "",
  id: 0,
  name: "",
  image: "",
  studiedWords: [],
  level: {
      easy: false,
      middle: false,
      hight: false
  },
  stressTime: 0,
  translate: false
}

const users: UserState[] = [];

// Middleware для проверки JWT токена
const authenticateToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ message: 'Требуется авторизация' });
    return;
  }

  try {
    const user = jwt.verify(token, JWT_SECRET) as { id: number; email: string };
    req.user = user;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Недействительный токен' });
  }
};

app.get("/user", authenticateToken, (async (req: Request, res: Response) => {
  const user = users.find(user => user.id === req.user?.id);
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  res.json({ ...user, password: undefined });
}) as RequestHandler);

app.put("/user", authenticateToken, (async (req: Request, res: Response) => {
  const { email, name, image, studiedWords, level, stressTime, translate } = req.body;
  const userId = req.user?.id;

  const user = users.find(user => user.id === userId);
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  user.email = email ?? user.email;
  user.name = name ?? user.name;
  user.image = image ?? user.image;
  user.studiedWords = studiedWords ?? user.studiedWords;
  user.level = { ...user.level, ...level };
  user.stressTime = stressTime ?? user.stressTime;
  user.translate = translate ?? user.translate;

  res.json({ message: "Данные пользователя успешно обновлены", user: { ...user, password: undefined } });
}) as RequestHandler);

// Маршрут для получения списка слов
app.get("/words", (req: Request, res: Response) => {
  res.json(words);
});

// Маршрут для получения списка пользователей (только для администратора)
app.get("/users", authenticateToken, (async (req: Request, res: Response) => {
  // Проверяем, является ли пользователь администратором
  const user = users.find(user => user.id === req.user?.id);
  if (!user || user.email !== 'admin@example.com') {
    return res.status(403).json({ message: "Доступ запрещен" });
  }

  // Возвращаем список пользователей без паролей
  const usersList = users.map(user => ({
    id: user.id,
    email: user.email,
    name: user.name,
    image: user.image,
    studiedWords: user.studiedWords,
    level: user.level,
    stressTime: user.stressTime,
    translate: user.translate
  }));

  res.json(usersList);
}) as RequestHandler);

// Маршрут для регистрации
app.post("/register", (async (req: Request, res: Response) => {
  const { email, password, name } = req.body;

  // Проверяем, существует ли пользователь
  if (users.find(user => user.email === email)) {
    return res.status(400).json({ message: "Пользователь уже существует" });
  }

  // Хешируем пароль
  const hashedPassword = await bcrypt.hash(password, 10);

  // Создаем нового пользователя
  const newUser: UserState = {
    id: users.length + 1,
    email: email,
    password: hashedPassword,
    name: name,
    image: "",
    studiedWords: [],
    level: {
      easy: false,
      middle: false,
      hight: false
    },
    stressTime: 0,
    translate: false,
    token: ''
  };

  users.push(newUser);

  // Создаем JWT токен
  const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET);
  newUser.token = token;

  res.status(201).json({ token, user: { ...newUser, password: undefined } });
}) as RequestHandler);

// Маршрут для авторизации
app.post("/login", (async (req: Request, res: Response) => {
  const { email, password } = req.body;

  // Ищем пользователя
  const user = users.find(user => user.email === email);
  if (!user || !user.password) {
    return res.status(400).json({ message: "Пользователь не найден" });
  }

  // Проверяем пароль
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ message: "Неверный пароль" });
  }

  // Создаем JWT токен
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
  user.token = token; // Обновляем токен пользователя

  res.json({ token, user: { ...user, password: undefined } });
}) as RequestHandler);

// Маршрут для получения изученных слов пользователя
app.get("/user/words", authenticateToken, (async (req: Request, res: Response) => {
  
  const user = users.find(user => user.id === req.user?.id);

  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  res.json(user.studiedWords);
}) as RequestHandler);

// Маршрут для добавления изученных слов
app.post("/user/words", authenticateToken, (async (req: Request, res: Response) => {
  const user = users.find(user => user.id === req.user?.id);
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  if (!Array.isArray(req.body) || req.body.length === 0) {
    return res.status(400).json({ message: "Некорректные данные" });
  }

  const newWords: WordState[] = req.body;
  
  // Создаём множество уже изученных слов для быстрого поиска
  const existingWordsSet = new Set(user.studiedWords.map(w => w.word));

  // Отфильтровываем только новые слова
  const wordsToAdd = newWords.filter(word => !existingWordsSet.has(word.word));

  if (wordsToAdd.length === 0) {
    return res.status(200).json({ message: "Все слова уже изучены" });
  }

  // Добавляем новые слова
  user.studiedWords.push(...wordsToAdd);

  res.status(201).json({ 
    message: "Добавлены новые слова",
    addedWords: wordsToAdd.map(w => w.word)
  });
}) as RequestHandler);

// Запуск сервера
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
