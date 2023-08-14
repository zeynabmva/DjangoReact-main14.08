import React, { useState } from 'react';
import ReactDOM from 'react-dom';
import { Routes, Route, useLocation } from "react-router-dom";
import "./App.css";
import "./Home.css";
import "./Responsive.css";
import Footer from "./components/Footer";
import Home from "./pages/Home";
import Headerr from "./components/Headerr";
import Blog from "./pages/Blog";
 
import About from "./pages/About";
import Blog_single from "./pages/Blog_single/";
import Contact from "./pages/Contact";
import Shop from "./pages/Shop";
import Shop_single from "./pages/Shop_single";
import Service from "./pages/Service";
import Service_single from "./pages/Service_single";
import { useEffect } from "react";
import { connect } from "react-redux";
import Team from "./pages/Team";
import AnimatedCursor from "react-animated-cursor";
import Delivery from "./pages/Delivery";
import BlogCreate from "./pages/BlogCreate";
import Recipe from './pages/recipe';
import Recipe_single from './pages/Recipe_single';
import TrueActivation from './pages/TrueActivation';
import axios from 'axios';

axios.defaults.xsrfCookieName='csrftoken';
axios.defaults.xsrfHeaderName='X_CSRFToken';
axios.defaults.withCredentials=true;
const client=axios.create({
  baseURL:'http://127.0.0.1:8000'
})


function App({ dispatch }) {
  const [currentUser,setCurrentUser]=useState()
  const [registrationToggle, setRegistrationToggle]=useState(false)
  const [email,setEmail]=useState('')
  const [username,setUsername]=useState('')
  const [password,setPassword]=useState('')

  useEffect(() => {
    fetch("http://127.0.0.1:8000/shop-product/list/")
      .then((a) => a.json())
      .then((a) =>
        dispatch({
          type: "SET_PRODUCTS",
          payload: a,
        })
      );
  });

  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  return (
    <>
      <div className="App">
        <AnimatedCursor
          innerSize={12}
          outerSize={14}
          color="37, 208, 65"
          outerAlpha={0.2}
          innerScale={1}
          outerScale={3}
        />
      </div>
      {pathname !== "/not-found" && <Headerr />}
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />}></Route>
        <Route path="/blog" element={<Blog />} />
        <Route path="/recipe" element={<Recipe />} />
        <Route
          path="/recipe/recipe_single/:id"
          element={<Recipe_single />}
        />
        <Route path="/blog/blog_single/:id" element={<Blog_single />}></Route>
        <Route path="/shop" element={<Shop />}></Route>
        <Route path="/shop-single/:id" element={<Shop_single />}></Route>
        <Route path="/services" element={<Service />}></Route>
        <Route path="/service-single" element={<Service_single />}></Route>
        <Route path="/contact-us" element={<Contact />}></Route>
        <Route path="/team" element={<Team />}></Route>
        <Route path="/delivery" element={<Delivery />}></Route>
        <Route path="/access-activation" element={<TrueActivation />}></Route>
        <Route path="/blog/create" element={<BlogCreate />}></Route>
        
      </Routes>
      {pathname !== "/not-found" && <Footer />}
    </>
  );
}

export default connect()(App);
