import React from "react";
import { useState, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useNavigate } from "react-router-dom";
import Modal from "../components/Modal";
import FavoriteModal from "../components/FavoriteModal";
import { connect } from "react-redux";
// import user from "../images/user.gif";
import LoginModal from "./LoginModal";
import RegistrationModal from "./RegistrationModal";
import SecondresgistrationModal from "./SecondresgistrationModal";

function Header({ basket }) {
  const [menuShown, setMenuShown] = useState(false);
  const [modalShown, setModalShown] = useState(false);
  const [favoriteModalShown, setFavoriteModalShown] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  const [isLogin, setIsLogin] = useState(false);
  const [regst, setRegst] = useState(false);
  const [regstVen, setRegstVen] = useState(false);
  const [data, setData] = useState([]);
  const [item, setItem] = useState("");
  const [filter, setFilter] = useState("");
  const [searchValue, setSearchValue] = useState("");
  const [dataFormInput, setDataFormInput] = useState({
    name: "",
    username: "",
    password: "",
    mail: "",
  });
  const [dataForm, setDataForm] = useState([]);

  const [dataFormInputVendor, setDataFormInputVendor] = useState({
    name: "",
    username: "",
    password: "",
    mail: "",
  });
  const [dataFormVendor, setDataFormVendor] = useState([]);

  const { pathname } = useLocation();

  const nav = useNavigate();
 
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response1 = await fetch('http://127.0.0.1:8000/shop-product/list/');
        const data = await response1.json();
        setData(data);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    fetchData();
  }, [])

  let f = data.filter((a) =>
    a.name.toLowerCase().includes(filter.toLowerCase())
  );

  const handleChange = (e) => {
    // setItem(e.target.value)
    setFilter(e);
    setSearchValue(e);
    let f = data.filter((a) =>
      a.name.toLowerCase().includes(filter.toLowerCase())
    );
  };

  const handleClick = (id, name) => {
    setSearchValue(name);
    nav(`shop-single/${id}`);
  };

  const handleLogin = () => {
    setIsLogin(true);
  };

  const handleSignUpVendor = () => {
    setIsLogin(false);
    setRegst(false);
    setRegstVen(true);
  };

  const handleSignUpExit = () => {
    setRegst(false);
    setIsLogin(false);
  };

  const handleSignUp = () => {
    setIsLogin(false);
    setRegst(true);
  };

  useEffect(() => {
    setMenuShown(false);
    // setSearchValue("")
    setFilter("");
  }, [pathname]);
  return (
    <>
      <header  className="">
        <div className="header ">
          <div className="header_main">
            <div className="logo_menu">
              <a href="#" className="header_logo">
                <img src="/static/organic_logo.svg" />
              </a>
              <input type="checkbox" id="menu_bar_input" />
              <ul className="menu">
                <li>
                  <NavLink to="/">Home</NavLink>
                </li>
                <li>
                  <NavLink to="/about">About Us</NavLink>
                </li>
                <li>
                  <NavLink to="/shop">Shop</NavLink>
                </li>
                <li className="has_dropdown">
                  <a>
                    Pages<i className="fa-solid fa-chevron-down"></i>
                  </a>
                  <ul className="dropdown">
                    <li>
                      <NavLink to="/services">Services</NavLink>
                    </li>
                    <li>
                      <NavLink to="/service-single">Service Single</NavLink>
                    </li>
                    <li>
                      <NavLink to="/recipe">Recipes</NavLink>
                    </li>
                    <li>
                      <NavLink to="/team">Our Team</NavLink>
                    </li>
                    <li>
                      <NavLink to="/blog">Blog</NavLink>
                    </li>
                  </ul>
                </li>
                <li>
                  <NavLink to="/contact-us">Contact Us</NavLink>
                </li>
              </ul>
            </div>
            <div className="search_cart position">
              <div
                onClick={() => setShowSearch(!showSearch)}
                className="input position"
              >
                <input
                  onChange={(e) => handleChange(e.target.value)}
                  type="text"
                  className="search"
                  value={searchValue}
                ></input>
                {showSearch && (
                  <ul className="scroll">
                    {f.map((item) => (
                      <li onClick={(e) => setItem(e.target.textContent)}>
                        {/* <Link to={`shop-single/${item.id}`}>{item.name}</Link> */}
                        <div onClick={() => handleClick(item.id, item.name)}>
                          {item.name}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
                <div className="search_icon">
                  <i className="fa-solid fa-magnifying-glass fa-beat-fade"></i>
                </div>
              </div>
              <div className="header_search"></div>
              <a
                onClick={() => setModalShown(!modalShown)}
                className="header_cart"
              >
                <div className="cart_image">
                  <img src="/static/Cart Icon.png" />
                </div>
                <div className="cart_text">Cart</div>
                <div className="cart_count">
                  {basket ? `(${basket.length})` : 0}
                </div>
              </a>
              <div className="favorite_in_header">
                <a onClick={() => setFavoriteModalShown(!favoriteModalShown)}>
                  <i className="fa fa-solid  fa-heart"></i>
                </a>
              </div>
              <div className="login_icon" onClick={handleLogin}>
                <img
                  width={50}
                  height={50}
                  style={{ marginLeft: "5px"}}
                  src={"/static/user.gif"}
                  alt=""
                />
              </div>

              <label className="hamburger_menu_icon" htmlFor="menu_bar_input">
                <i className="fa-solid fa-bars"></i>
              </label>

            </div>
          </div>
        </div>
      </header>

      {favoriteModalShown && (
        <FavoriteModal
          favoriteModalShown={favoriteModalShown}
          setFavoriteModalShown={setFavoriteModalShown}
        />
      )}

      {modalShown && (
        <Modal modalShown={modalShown} setModalShown={setModalShown} />
      )}
      
      {isLogin && (
        <LoginModal
          handleLogin={handleLogin}
          handleSignUp={handleSignUp}
          handleSignUpVendor={handleSignUpVendor}
          dataForm={dataForm}
          dataFormVendor={dataFormVendor}
        />
      )}
      {regst && (
        <RegistrationModal
          handleSignUpExit={handleSignUpExit}
          setDataFormInput={setDataFormInput}
          dataFormInput={dataFormInput}
          setDataForm={setDataForm}
        />
      )}
      {regstVen && (
        <SecondresgistrationModal
          setDataFormVendor={setDataFormVendor}
          dataFormVendor={dataFormVendor}
          dataForm={dataForm}
          setDataFormInputVendor={setDataFormInputVendor}
          handleSignUpExit={handleSignUpExit}
          dataFormInputVendor={dataFormInputVendor}
        />
      )}
    </>
  );
}
const t = (a) => a;
export default connect(t)(Header);
