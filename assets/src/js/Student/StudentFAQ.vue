<template>
  <v-container fluid>
    <div class="d-flex flex-row justify-space-between">
      <v-row justify="center">
        <v-col cols="12" md="11">
          <v-card>
            <v-card-title class="headline">
              <div class="d-flex justify-content-center align-items-center mr-2" style="height:50px;width:50px;
              background-color:#1976d2;">
              <v-icon color="white" small style="font-family:Arial">FAQ</v-icon>
            </div>
            Frequently Asked Question
          </v-card-title>
          <v-container fluid>
            <v-row>
              <v-col cols="12" sm="3">
                <v-text-field label="Search" v-model="searchText" outlined></v-text-field>
              </v-col>
            </v-row>
            <v-row class="mb-5">
              <v-expansion-panels class="mx-2">
                <v-expansion-panel v-for="(item,i) in filteredFaq" key="i">
                  <v-expansion-panel-header class="d-flex justify-content-start">
                    <v-col class="px-0" cols="1">
                      <v-icon x-large color="#6bbde9">mdi-numeric-{{i + 1}}-circle</v-icon>
                    </v-col>
                    <v-col cols="10">
                      <v-row class="mb-2 font-weight-bold">{{item['question']}}</v-row>
                      <v-row>{{item['answer']}}</v-row>
                    </v-col>
                  </v-expansion-panel-header>
                  <v-expansion-panel-content>
                    {{item['answer']}}
                  </v-expansion-panel-content>
                </v-expansion-panel>
              </v-expansion-panels>
            </v-row>
          </v-container>
        </v-card>
      </v-col>
    </v-row>

    <div class="float-right button-container">
      <div class="buttons">
        <v-row class="ma-2 mb-4">
          <button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#1976d2" icon>
            <v-icon color="white" x-large>add</v-icon>
          </button>
        </v-row>
        <v-row class="ma-2 mb-4">
          <button class="float-right ml-2 v-btn v-btn--depressed theme--light" style="background-color:#1976d2" icon>
            <v-icon color="white" x-large>question_answer</v-icon>
          </button>
        </v-row>
      </div>
    </div>

  </div>




</v-container>
</template>

<script>
import axios from 'axios'
export default {
  data() {
    return {
      searchText: '',
      Faq: [],
      editDialog: false,
      addDialog: false,
    }
  },

  mounted(){

this.getAllFaq()
  },

  computed: {

    filteredFaq(){

      return this.Faq.filter( data => data.question.toLowerCase().includes(this.searchText.toLowerCase()))
    }
  },

  methods: {

    async getAllFaq(){


    await axios.get('Faq/showAll').then(res => {

        if(res.data.faq){

          this.$set(this.$data, 'Faq', res.data.faq)

              console.log(this.Faq, 'faq')
        }


      })
    }
  }
}
</script>

<style lang="css">
</style>
