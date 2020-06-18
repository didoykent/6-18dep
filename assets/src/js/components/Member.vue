<template>
  <v-container>
    <v-row align-content="center" align="center">
      <v-container>
          <v-row>
              <v-col cols="12" sm="12" md="6" @click="$router.push('/MemberAddStudent2')">
                <v-card class="display-2" max-height="300px" height="300px">
                  <v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
                    STUDENTS
                 </v-row>
                </v-card>
              </v-col>
              <v-col cols="12" sm="12" md="6" @click="$router.push('/MemberTutor')">
                <v-card class="display-2"  max-height="300px" height="300px">
                    <v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
                    TUTORS
                  </v-row>
                </v-card>
              </v-col>
          </v-row>

          <v-row>
              <v-col cols="12" sm="12" md="6">
                <v-card class="display-2"  max-height="300px" height="300px">
                    <v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
                    ADMIN
                  </v-row>
                </v-card>
              </v-col>
              <v-col cols="12" sm="12" md="6">
                <v-card class="display-2"   max-height="300px" height="300px">
                    <v-row align="end" justify="end" class="pa-2 mr-3 fill-height">
                    ATTENDANCE
                  </v-row>
                </v-card>
              </v-col>
          </v-row>
        </v-container>
      </v-row>

  </v-container>

</template>

<script>
export default {

}
</script>

<style lang="css">
</style>
