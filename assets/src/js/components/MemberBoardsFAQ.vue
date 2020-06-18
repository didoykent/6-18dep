<template>
  <v-container fluid>
    <div class="d-flex flex-row justify-space-between">
    	<v-row justify="center">
        <v-col cols="12" md="11">
          <v-card>
            <v-card-title class="headline">
              <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
              background-color:#E91E63;">
              <v-icon color="white" small style="font-family:Arial">FAQ</v-icon>
            </div>
              Frequently Asked Question
            </v-card-title>
            <v-container fluid>
              <v-row>
                <v-col cols="12" sm="3">
                  <v-text-field label="Search" v-model="search" outlined></v-text-field>
                </v-col>
              </v-row>
              <v-row class="mb-5">
                <v-expansion-panels class="mx-2">
                    <v-expansion-panel v-for="(item,i) in Faq" key="i">
                      <v-expansion-panel-header class="d-flex justify-content-start" >
                        <v-col  class="px-0" cols="1"><v-icon x-large color="#fd999a">mdi-numeric-{{i + 1}}-circle</v-icon></v-col>
                        <v-col cols="10">
                          <v-row class="mb-2 font-weight-bold">{{item['question']}}</v-row>
                          <v-row>{{item['answer']}}</v-row>
                        </v-col>
                        <v-col cols="1"  >
                          <v-icon x-large color="#E91E63" @click="setFaq(item)">edit</v-icon>
                        </v-col>
                      </v-expansion-panel-header>
                      <v-expansion-panel-content>
                          {{item['answer']}}
                      </v-expansion-panel-content>
                    </v-expansion-panel>
                  </v-expansion-panels>
              </v-row>

              <v-row class="d-flex justify-content-end">
                <v-btn color="#E91E63" class="white--text mx-2" @click="addDialog = true">Add</v-btn>
              </v-row>

            </v-container>
          </v-card>
        </v-col>
    	</v-row>
    </div>

    <v-dialog v-model="editDialog" max-width="1000" max-height="500">
      <v-card>
        <v-card-title class="headline">
          <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
          background-color:#E91E63;">
        <v-icon color="white" small style="font-family:Arial">FAQ</v-icon>
        </div>
          <span>Frequently Asked Question</span>
        </v-card-title>
        <v-container fluid>
          <v-row>
            <v-col cols="12">
                <v-text-field v-model="currentFaq['question']" label="Question" placeholder="Question"></v-text-field>
            </v-col>
          </v-row>
          <v-row>
            <v-col cols="12">
              <v-textarea filled :placeholder="currentFaq['answer']" v-model="currentFaq['answer']"></v-textarea>
            </v-col>
          </v-row>
          <v-row class="d-flex justify-content-end">
            <v-btn text style="color:#E91E63" @click = "deleteFaq(currentFaq)">Delete</v-btn>
            <v-btn text style="color:#E91E63" @click="editDialog = false">Close</v-btn>
            <v-btn color="#E91E63" class="white--text mx-2" @click = "updateFaq(currentFaq)">Post</v-btn>
          </v-row>
        </v-container>
      </v-card>
    </v-dialog>

    <v-dialog v-model="addDialog" max-width="1000" max-height="500">
      <v-card>
        <v-card-title class="headline">
          <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
          background-color:#E91E63;">
        <v-icon color="white" small style="font-family:Arial">FAQ</v-icon>
        </div>
          <span>Frequently Asked Question</span>
        </v-card-title>
        <v-container fluid>
          <v-row>
            <v-col cols="12">
                <v-text-field v-model="Question" label="Question"></v-text-field>
            </v-col>
          </v-row>
          <v-row>
            <v-col cols="12">
              <v-textarea filled placeholder="Write here ..." v-model="Answer"></v-textarea>
            </v-col>
          </v-row>
          <v-row class="d-flex justify-content-end">
            <v-btn text style="color:#E91E63" @click="addDialog = false">Close</v-btn>
            <v-btn color="#E91E63" class="white--text mx-2" @click = "addFaq()">Save</v-btn>
          </v-row>
        </v-container>
      </v-card>
    </v-dialog>

  </v-container>

</template>

<script>

import axios from 'axios'
export default {
    data(){
      return{
        Faq: [],
        currentFaq: '',
        Question: '',
        Answer: '',
        editDialog: false,
        addDialog: false,
      }
    },

    mounted(){

        this.getAllFaq()
    },

    methods: {

      addFaq(){

        console.log(this.Question)
        console.log(this.Answer)

        if(this.Question && this.Answer){

            const form = new FormData()
            const Question = this.Question
            const Answer = this.Answer

            form.append('question', Question)
            form.append('answer', Answer)

            axios.post('Faq/addFaq', form).then(res => {

if(res.data.error ===false){

  location.reload()
}
              console.log(res.data)
            })
        }


      },

      getAllFaq(){


        axios.get('Faq/showAll').then(res => {

          if(res.data.faq){

            this.$set(this.$data, 'Faq', res.data.faq)
          }

          console.log(this.Faq, 'faq')
        })

      },

      setFaq(item){

        if(item){

        this.currentFaq = item

        this.editDialog = true

      }
      },

      updateFaq(currentFaq){




        if(currentFaq){

          console.log(currentFaq)

          const form = new FormData()

          form.append('question', currentFaq['question'])
          form.append('answer', currentFaq['answer'])
          form.append('faqid', currentFaq['faqid'])



          axios.post('Faq/updateFaq', form).then( res=> {

            console.log(res.data, 'data')
          })
        }

      },

      deleteFaq(currentFaq){


        if(currentFaq){

          const form  = new FormData()
          form.append('faqid', currentFaq['faqid'])

          axios.post('Faq/deleteFaq', form).then(res => {

            if(res.data.error ===false){

              location.reload()
            }

            console.log(res.data)
          })
        }
      }
    }
}
</script>

<style lang="css">
</style>
