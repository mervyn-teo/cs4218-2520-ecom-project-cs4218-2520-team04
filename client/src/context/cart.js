// Teo Kai Xiang, A0272558U
// Fixed bug with "React is not defined" error and improved robustness in case of invalid JSON in localStorage.

import React, { useState, useContext, createContext, useEffect } from "react";

const CartContext = createContext();
const CartProvider = ({ children }) => {
  const [cart, setCart] = useState([]);

  useEffect(() => {
    let existingCartItem = localStorage.getItem("cart");
    try {
      if (existingCartItem) setCart(JSON.parse(existingCartItem));
    } catch (error) {
      console.error("Error parsing cart from localStorage:", error);
      setCart([]);
    }
  }, []);

  return (
    <CartContext.Provider value={[cart, setCart]}>
      {children}
    </CartContext.Provider>
  );
};

// custom hook
const useCart = () => useContext(CartContext);

export { useCart, CartProvider };
