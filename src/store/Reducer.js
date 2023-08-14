const initialState = {
    products: [],
    basket: JSON.parse(localStorage.getItem("basket")) || [],
    favorite:JSON.parse(localStorage.getItem("favorite")) || [],
};

export default function Reducer(state = initialState, action) {
    switch (action.type) {
        case "SET_PRODUCTS":
            return { ...state, products: action.payload };
        case "SET_BASKET":
            return { ...state, basket: action.payload };
        case "SET_FAVORITE":
            return { ...state, favorite: action.payload };
        default:
            return state;
    }
}
