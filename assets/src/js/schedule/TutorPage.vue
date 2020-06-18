<template >
  <v-app>

  <div>

  <TutorNavbar></TutorNavbar>

  </div>
  <v-content style="padding: 0px;">
  <schedule></schedule>
  </v-content>
</v-app>
</template>

<script>
import TutorNavbar from '../components/TutorNavbar.vue'
import schedule from './Schedule.vue'
export default {

  components: {schedule, TutorNavbar},
  data(){
    return{
      userSettings: false,
      expand: false,
      menus: {
        dashboard: false,
        members: false,
        classes: false,
        boards: false
      },


    }
  },

  mounted(){

    console.log(this.$route)
  },

  watch: {
    $route(to, from) {
      console.log(to)
      console.log(from)
    }

  },

  methods: {
    setMenu(selectedMenu){
      for(var menu in this.menus){
        if(menu === selectedMenu){
          this.menus[menu] = !this.menus[menu]
        }
        else{
          this.menus[menu] = false
        }
      }
      console.log(this.menus)
    }
  }
}
</script>

<style>
/* Remove in 1.2 */
.v-datatable thead th.column.sortable i {
  vertical-align: unset;
}
</style>
