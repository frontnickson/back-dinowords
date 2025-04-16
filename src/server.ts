import express, { Request, Response, RequestHandler, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
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

const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET не определён");
}

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
  imageLink: string;
}

interface UserState {
  email: string;
  token: string;
  id: number;
  name: string;
  age: number;
  man: boolean;
  woman: boolean
  image: string;
  studiedWords: WordState[];
  studiedImage: WordState[];
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
  age: 0,
  man: false,
  woman: false,
  image: "",
  studiedWords: [],
  studiedImage: [],
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
  const { email, name, age, man, woman, image, studiedWords, level, stressTime, translate } = req.body;
  const userId = req.user?.id;

  const user = users.find(user => user.id === userId);
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  user.email = email ?? user.email;
  user.name = name ?? user.name;
  user.age = age ?? user.age;
  user.man = man ?? user.man;
  user.woman = woman ?? user.woman;
  user.image = image ?? user.image;
  user.studiedWords = studiedWords ?? user.studiedWords;
  user.level = { ...user.level, ...level };
  user.stressTime = stressTime ?? user.stressTime;
  user.translate = translate ?? user.translate;

  res.json({ message: "Данные пользователя успешно обновлены", user: { ...user, password: undefined } });
}) as RequestHandler);

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
    age: user.age,
    man: user.man,
    woman: user.woman,
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
  const { email, password, name, age, man, woman } = req.body;

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
    age: age,
    man: man,
    woman: woman,
    image: "",
    studiedWords: [],
    studiedImage: [],
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

// Маршрут (эндпоинт) для получения всех данных пользователя
app.get("/user/full", authenticateToken, (async (req: Request, res: Response) => {
  // Ищем пользователя в массиве users по его ID (полученному из токена)
  const user = users.find(user => user.id === req.user?.id);

  // Если пользователя нет, отправляем ошибку
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  // Если нашли, отправляем данные пользователя в ответе
  res.json(user);
}) as RequestHandler);

// Маршрут (эндпоинт) для обновления данных пользователя
app.put("/user/full", authenticateToken, (async (req: Request, res: Response) => {
  // Получаем ID пользователя из токена
  const userId = req.user?.id;

  // Получаем новые данные из тела запроса
  const { email, name, age, man, woman, image, studiedWords, level, stressTime, translate, password } = req.body;

  // Ищем пользователя в массиве по ID
  const user = users.find(user => user.id === userId);

  // Если пользователя нет, отправляем ошибку
  if (!user) return res.status(404).json({ message: "Пользователь не найден" });

  // Обновляем данные пользователя, если они были переданы в запросе
  user.email = email ?? user.email;
  user.name = name ?? user.name;
  user.age = age ?? user.age;
  user.man = man ?? user.man;
  user.woman = woman ?? user.woman;
  user.image = image ?? user.image;
  user.studiedWords = studiedWords ?? user.studiedWords;
  user.level = { ...user.level, ...level }; // Объединяем старые и новые значения уровня
  user.stressTime = stressTime ?? user.stressTime;
  user.translate = translate ?? user.translate;

  // Если пользователь передал новый пароль, хешируем его и обновляем
  if (password) {
    user.password = await bcrypt.hash(password, 10);
  }

  // Отправляем обновленные данные обратно клиенту
  res.json({ message: "Данные пользователя успешно обновлены", user });
}) as RequestHandler);

// Запускаем сервер на указанном порту
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
