import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
type Theme="dark"|"light";
const ThemeContext=createContext<{theme:Theme;toggleTheme:()=>void}>({theme:"dark",toggleTheme:()=>{}});
export function ThemeProvider({children}:{children:ReactNode}){const [theme,setTheme]=useState<Theme>(()=>{try{return localStorage.getItem("mirsad_theme")==="light"?"light":"dark"}catch{return "dark"}});useEffect(()=>{document.documentElement.dataset.theme=theme;try{localStorage.setItem("mirsad_theme",theme)}catch{}},[theme]);const value=useMemo(()=>({theme,toggleTheme:()=>setTheme(t=>t==="dark"?"light":"dark")}),[theme]);return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>}
export function useTheme(){return useContext(ThemeContext)}
