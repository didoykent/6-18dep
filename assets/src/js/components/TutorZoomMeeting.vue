<template>



<button type="button" name="button" @click="createMeeting">Create</button>
</template>

<script>

import axios from 'axios'
export default {

  data(){

    return{


    }
  },

  mounted(){


    axios.post('Uedu/zoomToken').then(res => {

      console.log(JSON.parse(res.data.substring(1)), 'zoom')
      if(res.data){

        localStorage.setItem('zoomToken', JSON.parse(res.data.substring(1)))
      }
    })




  },

  methods:{

    createMeeting(){

      if(localStorage.getItem('zoomToken')){

        const zoomToken = localStorage.getItem('zoomToken')

        axios({

  method:'post',
  url:'https://api.zoom.us/v2/users/me/meetings',
  data:{
    topic : "Let's learn Laravel",
    type : 2,
    start_time : "2020-05-05T20:30:00",
    duration : "30", // 30 mins
    password : "123456"

  },

  auth: {

       'bearer': zoomToken
   },

  headers: {
          'User-Agent': 'Zoom-Jwt-Request',
          'content-type': 'application/json'
      },
}).then(res => {

  console.log(res.data)
})


      }
    }
  }
}
</script>

<style lang="css" scoped>
</style>
