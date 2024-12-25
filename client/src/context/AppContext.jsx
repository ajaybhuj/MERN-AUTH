import { createContext, useEffect, useState } from "react";
import { toast } from "react-toastify";
import axios from "axios";
export const AppContent = createContext();

export const AppContextProvider = (props) => {
  const backendUrl = import.meta.env.VITE_BACKEND_URL;
  const [isLoggedin, setIsLoggedin] = useState(false);
  const [userData, setUserData] = useState(false);

  const getAuthState = async () => {
    try {
      const { data } = await axios.get(
        backendUrl + "/api/auth/is-authenticated"
      );
      if (data.success) {
        setIsLoggedin(true);
        getUserData();
      }
    } catch (error) {
      toast.error(error.message);
    }
  };
  useEffect(() => {
    getAuthState();
  }, []);

  const getUserData = async () => {
    try {
      const { data } = await axios.get(backendUrl + "/api/user/data");
      data.success ? setUserData(data.userData) : toast.error(data.message);
    } catch (error) {
      toast.error(error.message);
    }
  };

  const value = {
    backendUrl,
    isLoggedin,
    userData,
    setIsLoggedin,
    getUserData,
    setUserData,
  };
  return (
    <AppContent.Provider value={value}>{props.children}</AppContent.Provider>
  );
};