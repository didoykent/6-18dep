import Vue from 'vue'
import App from './App.vue'
import Vuetify from 'vuetify'
import 'vuetify/dist/vuetify.min.css'
import '@mdi/font/css/materialdesignicons.css'
import router from './router'
import store from './store'
import axios from 'axios'
import VueSocketIO from 'vue-socket.io'
Vue.use(Vuetify)

Vue.use(new VueSocketIO({
    debug: true,
    connection: 'http://localhost:7740',


}))



axios.interceptors.request.use(function(config){




  let token =  localStorage.getItem('token')




if(localStorage.getItem('token')){



  config.headers.Authorization = 'Bearer '+ localStorage.getItem('token');


}


  return config;
}, function(error){


    return Promise.reject(error);


});

axios.interceptors.response.use(function (response) {
    // Do something with response data

    return response

  }, function (error) {

    if(error.response.status === 400 || error.response.status === 401 || error.response.status === 403){


    if(error.response.data.error === "token_not_provided"){

localStorage.clear();
    location.reload()
    }
    }
    // Do something with response error
    return Promise.reject(error);
  });


const app = new Vue({

  el: '#app',

  router,
  vuetify: new Vuetify({

    icons: {
       iconfont: 'mdi',
     },
  }),



store,

  render: h => h(App)



}).$mount('#app')
