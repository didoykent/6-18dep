import Vue from 'vue'
import App from './App.vue'
import 'vuetify/dist/vuetify.min.css'
import '@mdi/font/css/materialdesignicons.css'
import Vuetify from 'vuetify'

Vue.use(Vuetify)

new Vue({

  vuetify: new Vuetify({

    icons: {
       iconfont: 'mdi',
     },
  }),

  render: h => h(App)
}).$mount('#app')
