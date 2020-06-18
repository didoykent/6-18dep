<template>


      <v-container
        class="fill-height"
        fluid
      >
        <v-row
          align="center"
          justify="center"
        >
          <v-col
            cols="12"
            sm="8"
            md="4"
          >
            <v-card class="elevation-12">
              <v-toolbar
                color="primary"
                dark
                flat
              >
                <v-toolbar-title>Login form</v-toolbar-title>
                <v-spacer />

              </v-toolbar>
              <v-card-text>
                <v-form>

                  <span v-if = "Object.keys(err).length">{{err}}</span>
                  <v-text-field
                    label="Login"
                    name="login"
                    v-model = "User.id"
                    type="text"
                  />

                  <v-text-field
                    id="password"
                    label="Password"
                    name="password"
                    v-model = "User.pw"
                    type="password"
                  />
                </v-form>
              </v-card-text>
              <v-card-actions>
                <v-spacer />
                <v-btn color="primary" @click = "signIn">Login</v-btn>
              </v-card-actions>
            </v-card>
          </v-col>
        </v-row>
      </v-container>


</template>

<script>

import Vue from 'vue'

import axios from 'axios'
  export default {
    props: {
      source: String,
    },

    data(){
      return {




      User: [],
      err: {}

    }
    },

    mounted(){


    },

    methods: {

      signIn(){

        let form = new FormData()


        if(this.User.id){
        form.append('id', this.User.id)

        }

        if(this.User.pw){

          form.append('pw', this.User.pw)
        }


          axios.post('Uedu/SignIn', form).then(res => {




              const  {token, user, msg} = JSON.parse(res.data.substring(1))

            if(token){

              this.$store.dispatch('signIn', {token: token, user: user})
            }

            if(msg){

              this.$set(this.$data, 'err', msg)
            }


                this.User = []



          }).catch(err => {

            console.log(err)
          })





    }

}
  }
</script>
