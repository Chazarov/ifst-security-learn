import { useEffect, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const store = {
  get: () => ({
    access: localStorage.getItem("access"),
    refresh: localStorage.getItem("refresh"),
    role: localStorage.getItem("role"),
  }),
  set: (access, refresh, role) => {
    localStorage.setItem("access", access);
    localStorage.setItem("refresh", refresh);
    localStorage.setItem("role", role);
  },
  clear: () => {
    localStorage.removeItem("access");
    localStorage.removeItem("refresh");
    localStorage.removeItem("role");
  },
};

async function api(path, opts = {}, token) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, { ...opts, headers });
  if (res.status === 401 && store.get().refresh) {
    const r = await fetch(`${API}/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh: store.get().refresh }),
    });
    if (r.ok) {
      const data = await r.json();
      store.set(data.access, data.refresh, store.get().role);
      headers.Authorization = `Bearer ${data.access}`;
      return fetch(`${API}${path}`, { ...opts, headers });
    }
    store.clear();
  }
  return res;
}

export default function App() {
  const [user, setUser] = useState(null);
  const [login, setLogin] = useState({ username: "", password: "" });
  const [reg, setReg] = useState({ username: "", password: "" });
  const [revoke, setRevoke] = useState("");
  const [cat, setCat] = useState("");
  const [err, setErr] = useState("");

  const loadMe = async () => {
    const { access } = store.get();
    if (!access) return setUser(null);
    const res = await api("/me", {}, access);
    if (!res.ok) {
      store.clear();
      return setUser(null);
    }
    setUser(await res.json());
  };

  useEffect(() => {
    loadMe();
  }, []);

  const loadCat = async () => {
    const { access } = store.get();
    const res = await api("/cat", {}, access);
    if (!res.ok) throw new Error("Нет доступа к картинке");
    const blob = await res.blob();
    setCat(URL.createObjectURL(blob));
  };

  useEffect(() => {
    if (user) loadCat().catch((e) => setErr(e.message));
  }, [user]);

  const doLogin = async (e) => {
    e.preventDefault();
    setErr("");
    const res = await fetch(`${API}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(login),
    });
    if (!res.ok) return setErr("Неверный логин или пароль");
    const data = await res.json();
    store.set(data.access, data.refresh, data.role);
    setUser({ username: login.username, role: data.role });
  };

  const doRegister = async (e) => {
    e.preventDefault();
    setErr("");
    const res = await fetch(`${API}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(reg),
    });
    if (!res.ok) return setErr("Не удалось зарегистрироваться");
    setLogin(reg);
    setReg({ username: "", password: "" });
  };

  const doLogout = async () => {
    const { refresh, access } = store.get();
    if (refresh) {
      await api("/logout", { method: "POST", body: JSON.stringify({ refresh }) }, access);
    }
    store.clear();
    setUser(null);
    setCat("");
  };

  const doRevoke = async (e) => {
    e.preventDefault();
    const { access } = store.get();
    const res = await api(
      "/admin/revoke",
      { method: "POST", body: JSON.stringify({ username: revoke }) },
      access
    );
    setErr(res.ok ? `Токены ${revoke} отозваны` : "Ошибка отзыва");
  };

  if (!user) {
    return (
      <div style={{ maxWidth: 360, margin: "40px auto", fontFamily: "sans-serif" }}>
        <h2>Вход</h2>
        <form onSubmit={doLogin}>
          <input
            placeholder="Логин"
            value={login.username}
            onChange={(e) => setLogin({ ...login, username: e.target.value })}
            style={{ display: "block", width: "100%", marginBottom: 8 }}
          />
          <input
            type="password"
            placeholder="Пароль"
            value={login.password}
            onChange={(e) => setLogin({ ...login, password: e.target.value })}
            style={{ display: "block", width: "100%", marginBottom: 8 }}
          />
          <button type="submit">Войти</button>
        </form>
        <h3 style={{ marginTop: 24 }}>Регистрация</h3>
        <form onSubmit={doRegister}>
          <input
            placeholder="Логин"
            value={reg.username}
            onChange={(e) => setReg({ ...reg, username: e.target.value })}
            style={{ display: "block", width: "100%", marginBottom: 8 }}
          />
          <input
            type="password"
            placeholder="Пароль"
            value={reg.password}
            onChange={(e) => setReg({ ...reg, password: e.target.value })}
            style={{ display: "block", width: "100%", marginBottom: 8 }}
          />
          <button type="submit">Зарегистрироваться</button>
        </form>
        {err && <p style={{ color: "crimson" }}>{err}</p>}
        <p style={{ fontSize: 12, color: "#666", marginTop: 16 }}>
          Токены: localStorage (уязвимость XSS → кража токенов)
        </p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 520, margin: "40px auto", fontFamily: "sans-serif" }}>
      <h2>Привет, {user.username}</h2>
      <p>Роль: {user.role}</p>
      <button onClick={doLogout}>Выйти</button>
      {cat && (
        <div style={{ marginTop: 16 }}>
          <img src={cat} alt="кот" style={{ maxWidth: "100%" }} />
        </div>
      )}
      {user.role === "admin" && (
        <form onSubmit={doRevoke} style={{ marginTop: 24 }}>
          <h3>Отозвать токены пользователя</h3>
          <input
            placeholder="Логин"
            value={revoke}
            onChange={(e) => setRevoke(e.target.value)}
            style={{ marginRight: 8 }}
          />
          <button type="submit">Отозвать</button>
        </form>
      )}
      {err && <p style={{ color: user.role === "admin" ? "green" : "crimson" }}>{err}</p>}
      <p style={{ fontSize: 12, color: "#666", marginTop: 16 }}>
        Access ~1 мин → автообновление через refresh
      </p>
    </div>
  );
}
