
import { initializeApp } from "firebase/app";
import {getAuth, GoogleAuthProvider} from "firebase/auth"

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_APIKEY,
 authDomain: "examnotesai-d2661.firebaseapp.com",
  projectId: "examnotesai-d2661",
  storageBucket: "examnotesai-d2661.firebasestorage.app",
  messagingSenderId: "333187157652",
  appId: "1:333187157652:web:cfe123ddb61f99fae4ee81",
  measurementId: "G-KC4VF1S8SE"
};



const app = initializeApp(firebaseConfig);

const auth = getAuth(app)

const provider = new GoogleAuthProvider()

export {auth , provider}