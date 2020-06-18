<template>
  <v-container fluid style="height:100%">
    <v-row class="mt-3 ml-2">
      <v-col cols="12" sm="4" md="2" justify="center" class=" nav px-0">
        <v-btn :style="buttonColor1" block text @click="navClick($event)">My Members</v-btn>
      </v-col>
      <v-divider vertical></v-divider>
      <v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav px-0">
        <v-btn :style="buttonColor2" block text @click="navClick($event)">PH Tutors</v-btn>
      </v-col>
      <v-divider vertical></v-divider>
      <v-col cols="12" sm="4" md="2" align="center" justify="center" class="nav px-0">
        <v-btn :style="buttonColor3"  block text @click="navClick($event)">KR Admin</v-btn>
      </v-col>
    </v-row>
    <v-row style="height:100%" align="stretch">
      <TeamMemberMyMember v-if="currentComponent === 'TeamMemberMyMember'"></TeamMemberMyMember>
      <TeamMemberKRAdmin v-if="currentComponent === 'TeamMemberKRAdmin'"></TeamMemberKRAdmin>
      <TeamMemberPHTutors v-if="currentComponent === 'TeamMemberPHTutors'"></TeamMemberPHTutors>
    </v-row>
  </v-container>
</template>

<script>
import TeamMemberMyMember from './TeamMemberMyMember'
import TeamMemberKRAdmin from './TeamMemberKRAdmin'
import TeamMemberPHTutors from './TeamMemberPHTutors'

export default {

  components: {
    TeamMemberMyMember,
    TeamMemberKRAdmin,
    TeamMemberPHTutors,
  },


  data: vm => ({
    currentComponent: 'TeamMemberMyMember',
    buttonColor1: '',
    buttonColor2: '',
    buttonColor3: ''
  }),

  mounted(){
    console.log('a')
    if(this.currentComponent == 'TeamMemberMyMember'){
      this.buttonColor1 = 'background-color:#E91E63;color:white'
      this.buttonColor2 = ''
      this.buttonColor3 = ''
    }
  },

  methods: {
    navClick(selected) {
      if (selected.target.innerText == 'MY MEMBERS') {
        this.currentComponent = 'TeamMemberMyMember'
        this.buttonColor1 = 'background-color:#E91E63;color:white'
        this.buttonColor2 = ''
        this.buttonColor3 = ''
      } else if (selected.target.innerText == 'PH TUTORS') {
        this.currentComponent = 'TeamMemberPHTutors'
        this.buttonColor1 = ''
        this.buttonColor2 = 'background-color:#E91E63;color:white'
        this.buttonColor3 = ''
      } else if (selected.target.innerText == 'KR ADMIN') {
        this.currentComponent = 'TeamMemberKRAdmin'
        this.buttonColor1 = ''
        this.buttonColor2 = ''
        this.buttonColor3 = 'background-color:#E91E63;color:white'
      }

      console.log(this.currentComponent)
    },
  }
}
</script>

<style lang="css">
</style>
